package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// The LAN web gateway serves the same phone PWA as the Cloudflare Access
// listener, but for browsers on the home network. Instead of a Cloudflare
// Access JWT it uses one operator-chosen password and an HttpOnly session
// cookie. It is deliberately SMS/status only: dialing, media, USB, AT and
// administrator routes never join this listener.
const (
	lanWebLoginPagePath     = "/lan/login"
	lanWebLoginAPIPath      = "/api/remote/v1/lan/login"
	lanWebLogoutAPIPath     = "/api/remote/v1/lan/logout"
	lanWebSessionCookie     = "maccellular_lan_session"
	lanWebSessionTTL        = 30 * 24 * time.Hour
	lanWebMaxPasswordBytes  = 1 << 10
	lanWebMinPasswordRunes  = 10
	lanWebMaxLoginBodyBytes = 4 << 10
	lanWebMaxSessions       = 64
	// Brute-force protection: a client address is locked after a burst of
	// failures, and the whole listener is locked when failures from many
	// addresses accumulate (spoofed sources on a hostile LAN).
	lanWebFailureWindow     = 15 * time.Minute
	lanWebMaxFailuresPerIP  = 5
	lanWebMaxFailuresGlobal = 30
)

type lanWebFlagConfig struct {
	Listen       string
	PasswordFile string
	Control      bool
	TLSCertFile  string
	TLSKeyFile   string
	Hosts        string
	SessionsFile string
}

type lanWebStartupConfig struct {
	Listen       string
	Control      bool
	TLSCertFile  string
	TLSKeyFile   string
	ExtraHosts   map[string]struct{}
	SessionsFile string
	passwordHash [sha256.Size]byte
}

func (c *lanWebStartupConfig) TLS() bool {
	return c != nil && c.TLSCertFile != "" && c.TLSKeyFile != ""
}

func parseLANWebStartupConfig(flags lanWebFlagConfig) (*lanWebStartupConfig, error) {
	listen := strings.TrimSpace(flags.Listen)
	passwordPath := strings.TrimSpace(flags.PasswordFile)
	certPath := strings.TrimSpace(flags.TLSCertFile)
	keyPath := strings.TrimSpace(flags.TLSKeyFile)
	configured := listen != "" || passwordPath != "" || flags.Control || certPath != "" ||
		keyPath != "" || strings.TrimSpace(flags.Hosts) != "" || strings.TrimSpace(flags.SessionsFile) != ""
	if !configured {
		return nil, nil
	}
	if listen == "" {
		return nil, errors.New("LAN web requires -lan-web-listen")
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil || port == "" || port == "0" {
		return nil, errors.New("LAN web listen address must be host:port with a fixed port")
	}
	if host != "" && net.ParseIP(host) == nil {
		return nil, errors.New("LAN web listen host must be an IP literal or empty")
	}
	if passwordPath == "" || !filepath.IsAbs(passwordPath) {
		return nil, errors.New("LAN web requires an absolute -lan-web-password-file")
	}
	if (certPath == "") != (keyPath == "") {
		return nil, errors.New("LAN web TLS requires both certificate and key files")
	}
	if certPath != "" && (!filepath.IsAbs(certPath) || !filepath.IsAbs(keyPath)) {
		return nil, errors.New("LAN web TLS certificate and key paths must be absolute")
	}
	hash, err := readLANWebPasswordHash(passwordPath)
	if err != nil {
		return nil, fmt.Errorf("LAN web password: %w", err)
	}
	extra := make(map[string]struct{})
	for _, raw := range strings.Split(flags.Hosts, ",") {
		candidate := canonicalRemoteHost(raw)
		if candidate == "" {
			continue
		}
		if strings.ContainsAny(candidate, "/:@[] ") {
			return nil, errors.New("LAN web hosts must be plain DNS names")
		}
		extra[candidate] = struct{}{}
	}
	sessionsFile := strings.TrimSpace(flags.SessionsFile)
	if sessionsFile == "" {
		sessionsFile = defaultLANWebSessionsFile()
	}
	if sessionsFile != "" && !filepath.IsAbs(sessionsFile) {
		return nil, errors.New("LAN web sessions file must be an absolute path")
	}
	startup := &lanWebStartupConfig{
		Listen: listen, Control: flags.Control, TLSCertFile: certPath, TLSKeyFile: keyPath,
		ExtraHosts: extra, SessionsFile: sessionsFile, passwordHash: hash,
	}
	return startup, nil
}

func defaultLANWebSessionsFile() string {
	base, err := os.UserConfigDir()
	if err != nil || strings.TrimSpace(base) == "" {
		return ""
	}
	return filepath.Join(base, "MacCellular", "lan-web", "sessions.json")
}

func readLANWebPasswordHash(path string) ([sha256.Size]byte, error) {
	var hash [sha256.Size]byte
	data, err := readExternalVoicePasswordFile(path, lanWebMaxPasswordBytes)
	if err != nil {
		return hash, err
	}
	defer func() {
		for index := range data {
			data[index] = 0
		}
	}()
	if len(data) > 0 && data[len(data)-1] == '\n' {
		data = data[:len(data)-1]
	}
	password := string(data)
	if password == "" || !utf8.ValidString(password) || strings.TrimSpace(password) != password ||
		strings.ContainsAny(password, "\x00\r\n") {
		return hash, errors.New("password file must contain exactly one non-empty line")
	}
	if utf8.RuneCountInString(password) < lanWebMinPasswordRunes {
		return hash, fmt.Errorf("password must be at least %d characters", lanWebMinPasswordRunes)
	}
	return sha256.Sum256(data), nil
}

// lanWebHostAllowed rejects DNS-rebinding style hosts: only loopback, private,
// link-local and ULA IP literals, mDNS/home suffixes, single-label names and
// explicitly configured hostnames may address the LAN listener.
func lanWebHostAllowed(rawHost string, extra map[string]struct{}) bool {
	host := canonicalRemoteHost(rawHost)
	if host == "" {
		return false
	}
	if _, ok := extra[host]; ok {
		return true
	}
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
	}
	if strings.ContainsAny(host, "/:@[] ") {
		return false
	}
	if !strings.Contains(host, ".") {
		return true
	}
	for _, suffix := range []string{".local", ".home.arpa", ".lan", ".home", ".internal"} {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

type lanWebSession struct {
	Identity  string    `json:"identity"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Client    string    `json:"client,omitempty"`
}

type lanWebFailureRecord struct {
	times []time.Time
}

type lanWebAuth struct {
	mu           sync.Mutex
	passwordHash [sha256.Size]byte
	sessions     map[string]lanWebSession // key: hex(sha256(token))
	sessionsFile string
	failures     map[string]*lanWebFailureRecord
	global       lanWebFailureRecord
	now          func() time.Time
}

func (*lanWebAuth) String() string   { return "lanWebAuth{redacted}" }
func (*lanWebAuth) GoString() string { return "lanWebAuth{redacted}" }

func newLANWebAuth(config *lanWebStartupConfig) (*lanWebAuth, error) {
	auth := &lanWebAuth{
		passwordHash: config.passwordHash,
		sessions:     make(map[string]lanWebSession),
		sessionsFile: config.SessionsFile,
		failures:     make(map[string]*lanWebFailureRecord),
		now:          time.Now,
	}
	if auth.sessionsFile != "" {
		if err := auth.loadSessions(); err != nil {
			return nil, err
		}
	}
	return auth, nil
}

func (m *lanWebAuth) loadSessions() error {
	dir := filepath.Dir(m.sessionsFile)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create LAN web session directory: %w", err)
	}
	info, err := os.Lstat(m.sessionsFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("LAN web sessions file must be a regular file")
	}
	data, err := os.ReadFile(m.sessionsFile)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	var stored map[string]lanWebSession
	if err := json.Unmarshal(data, &stored); err != nil {
		// A corrupt session file only costs every phone one more login.
		log.Printf("LAN web session store was unreadable and has been reset")
		return nil
	}
	now := m.now()
	for key, session := range stored {
		if len(key) != hex.EncodedLen(sha256.Size) || !session.ExpiresAt.After(now) {
			continue
		}
		m.sessions[key] = session
	}
	return nil
}

func (m *lanWebAuth) persistLocked() {
	if m.sessionsFile == "" {
		return
	}
	data, err := json.Marshal(m.sessions)
	if err != nil {
		return
	}
	tmp := m.sessionsFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		log.Printf("LAN web session store write failed: %v", err)
		return
	}
	if err := os.Rename(tmp, m.sessionsFile); err != nil {
		log.Printf("LAN web session store rename failed: %v", err)
	}
}

func (m *lanWebAuth) pruneLocked(now time.Time) {
	for key, session := range m.sessions {
		if !session.ExpiresAt.After(now) {
			delete(m.sessions, key)
		}
	}
	cutoff := now.Add(-lanWebFailureWindow)
	for ip, record := range m.failures {
		record.times = trimTimes(record.times, cutoff)
		if len(record.times) == 0 {
			delete(m.failures, ip)
		}
	}
	m.global.times = trimTimes(m.global.times, cutoff)
}

func trimTimes(times []time.Time, cutoff time.Time) []time.Time {
	kept := times[:0]
	for _, moment := range times {
		if moment.After(cutoff) {
			kept = append(kept, moment)
		}
	}
	return kept
}

func (m *lanWebAuth) locked(client string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneLocked(m.now())
	if len(m.global.times) >= lanWebMaxFailuresGlobal {
		return true
	}
	record := m.failures[client]
	return record != nil && len(record.times) >= lanWebMaxFailuresPerIP
}

// Login compares the password in constant time and, on success, issues a new
// random session token. The caller receives the raw token exactly once; only
// its hash is stored.
func (m *lanWebAuth) Login(password, client string) (string, bool) {
	candidate := sha256.Sum256([]byte(password))
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	m.pruneLocked(now)
	if len(m.global.times) >= lanWebMaxFailuresGlobal {
		return "", false
	}
	if record := m.failures[client]; record != nil && len(record.times) >= lanWebMaxFailuresPerIP {
		return "", false
	}
	if subtle.ConstantTimeCompare(candidate[:], m.passwordHash[:]) != 1 {
		record := m.failures[client]
		if record == nil {
			record = &lanWebFailureRecord{}
			m.failures[client] = record
		}
		record.times = append(record.times, now)
		m.global.times = append(m.global.times, now)
		return "", false
	}
	delete(m.failures, client)
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", false
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	key := lanWebSessionKey(token)
	identity := "lan-" + key[:8]
	if len(m.sessions) >= lanWebMaxSessions {
		m.evictOldestLocked()
	}
	m.sessions[key] = lanWebSession{
		Identity: identity, CreatedAt: now, ExpiresAt: now.Add(lanWebSessionTTL), Client: client,
	}
	m.persistLocked()
	return token, true
}

func (m *lanWebAuth) evictOldestLocked() {
	oldestKey := ""
	var oldest time.Time
	for key, session := range m.sessions {
		if oldestKey == "" || session.CreatedAt.Before(oldest) {
			oldestKey, oldest = key, session.CreatedAt
		}
	}
	if oldestKey != "" {
		delete(m.sessions, oldestKey)
	}
}

func lanWebSessionKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (m *lanWebAuth) Lookup(token string) (lanWebSession, bool) {
	token = strings.TrimSpace(token)
	if token == "" || len(token) > 128 {
		return lanWebSession{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	session, ok := m.sessions[lanWebSessionKey(token)]
	if !ok || !session.ExpiresAt.After(now) {
		return lanWebSession{}, false
	}
	return session, true
}

func (m *lanWebAuth) Revoke(token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.sessions[lanWebSessionKey(token)]; ok {
		delete(m.sessions, lanWebSessionKey(token))
		m.persistLocked()
	}
}

func (m *lanWebAuth) ActiveSessions() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneLocked(m.now())
	return len(m.sessions)
}

func (a *app) configureLANWeb(config *lanWebStartupConfig, ledgerPath ...string) error {
	if config == nil {
		a.lanWeb = nil
		a.lanWebAuth = nil
		return nil
	}
	auth, err := newLANWebAuth(config)
	if err != nil {
		return err
	}
	if a.remoteCSRF == nil {
		a.remoteCSRF = newRemoteCSRFStore()
	}
	if a.remoteLedger == nil {
		path := ""
		if len(ledgerPath) > 0 {
			path = strings.TrimSpace(ledgerPath[0])
		}
		if path == "" {
			path, err = remoteOperationLedgerPath()
			if err != nil {
				return fmt.Errorf("LAN web operation ledger path: %w", err)
			}
		}
		ledger, err := openRemoteOperationLedger(path)
		if err != nil {
			return fmt.Errorf("LAN web operation ledger: %w", err)
		}
		a.remoteLedger = ledger
	}
	a.lanWeb = config
	a.lanWebAuth = auth
	return nil
}

var errLANWebLoginRequired = errors.New("LAN web login required")

func lanWebClientAddress(r *http.Request) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return host
}

func (a *app) authorizeLANWebRequest(r *http.Request) (remoteAuthorization, error) {
	if a.lanWeb == nil || a.lanWebAuth == nil || r == nil {
		return remoteAuthorization{}, errRemoteBrowserUnauthorized
	}
	if !lanWebHostAllowed(r.Host, a.lanWeb.ExtraHosts) {
		return remoteAuthorization{}, errRemoteBrowserUnauthorized
	}
	cookie, err := r.Cookie(lanWebSessionCookie)
	if err != nil || cookie == nil {
		return remoteAuthorization{}, errLANWebLoginRequired
	}
	session, ok := a.lanWebAuth.Lookup(cookie.Value)
	if !ok {
		return remoteAuthorization{}, errLANWebLoginRequired
	}
	actions := map[string]bool{"status.read": true, "sms.read": true}
	if a.lanWeb.Control {
		actions["sms.send"] = true
	}
	return remoteAuthorization{Identity: session.Identity, Actions: actions}, nil
}

func isLANWebGatewayPath(path string) bool {
	if path == "/" || path == "/remote" || strings.HasPrefix(path, "/remote/") {
		return true
	}
	switch path {
	case "/api/remote/v1/session",
		"/api/remote/v1/snapshot",
		"/api/remote/v1/sms/sync",
		"/api/remote/v1/sms/send",
		"/api/remote/v1/sms/refresh":
		return true
	}
	return false
}

func lanWebRequestIsNavigation(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		return false
	}
	if mode := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Mode"))); mode != "" {
		return mode == "navigate"
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

func (a *app) lanWebUnauthorized(w http.ResponseWriter, r *http.Request, err error) bool {
	if !errors.Is(err, errLANWebLoginRequired) {
		return false
	}
	if lanWebRequestIsNavigation(r) {
		target := lanWebLoginPagePath
		if next := r.URL.RequestURI(); next != "" && next != "/" && strings.HasPrefix(next, "/") &&
			!strings.HasPrefix(next, "//") {
			target += "?next=" + url.QueryEscape(next)
		}
		http.Redirect(w, r, target, http.StatusSeeOther)
		return true
	}
	w.Header().Set("X-MacCellular-Login", lanWebLoginPagePath)
	writeJSON(w, http.StatusUnauthorized, map[string]string{
		"error": "login required", "code": "login_required", "login_url": lanWebLoginPagePath,
	})
	return true
}

func (a *app) lanWebRoutes() http.Handler {
	if a.lanWeb == nil || a.lanWebAuth == nil {
		return http.NotFoundHandler()
	}
	protected := a.remoteBrowserSecurityHeaders(a.remoteBrowserRoutes(true), remoteBrowserSecurityPolicy{
		HostAllowed:         func(host string) bool { return lanWebHostAllowed(host, a.lanWeb.ExtraHosts) },
		PlainHTTPOrigin:     !a.lanWeb.TLS(),
		Control:             a.lanWeb.Control,
		Transport:           "lan",
		SMSOnly:             true,
		NotFoundUnknownPath: true,
		PathAllowed:         isLANWebGatewayPath,
		Authorize:           a.authorizeLANWebRequest,
		AuthorizationStatus: func(error) int { return http.StatusUnauthorized },
		Unauthorized:        a.lanWebUnauthorized,
	})
	loginAssets, err := fs.Sub(webAssets, "lan")
	if err != nil {
		panic(fmt.Sprintf("open embedded LAN login page: %v", err))
	}
	assetHandler := newRemoteAssetHandler(loginAssets)
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+lanWebLoginPagePath, func(w http.ResponseWriter, r *http.Request) {
		if _, err := a.authorizeLANWebRequest(r); err == nil {
			http.Redirect(w, r, "/remote/", http.StatusSeeOther)
			return
		}
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/login.html"
		assetHandler.ServeHTTP(w, r2)
	})
	// The login page shows the product icon before any session exists; serve
	// that one embedded file without authentication under the /lan/ prefix.
	mux.HandleFunc("GET /lan/icon.svg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "private, max-age=86400")
		http.ServeFileFS(w, r, webAssets, "remote/icon.svg")
	})
	mux.Handle("GET /lan/", http.StripPrefix("/lan/", assetHandler))
	mux.HandleFunc("POST "+lanWebLoginAPIPath, a.lanWebLogin)
	mux.HandleFunc("POST "+lanWebLogoutAPIPath, a.lanWebLogout)
	mux.Handle("/", protected)
	return a.lanWebPublicHeaders(mux)
}

// lanWebPublicHeaders applies the browser hardening headers to the
// pre-authentication login surface as well; the authenticated subtree sets the
// same headers again through remoteBrowserSecurityHeaders.
func (a *app) lanWebPublicHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !lanWebHostAllowed(r.Host, a.lanWeb.ExtraHosts) {
			http.Error(w, "LAN host required", http.StatusForbidden)
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; connect-src 'self'; img-src 'self'; manifest-src 'self'; script-src 'self'; style-src 'self'")
		if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == lanWebLoginPagePath {
			w.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// lanWebRequestIsSameOrigin accepts browser requests whose Origin matches the
// request host (any scheme the listener actually serves) and non-browser
// clients that send no Origin at all. Browsers always attach Origin to POST.
func lanWebRequestIsSameOrigin(r *http.Request) bool {
	if site, ok := remoteSingleHeader(r.Header, "Sec-Fetch-Site"); ok {
		switch strings.ToLower(site) {
		case "same-origin", "none":
		default:
			return false
		}
	}
	originValue := strings.TrimSpace(r.Header.Get("Origin"))
	if originValue == "" {
		return true
	}
	origin, err := url.Parse(originValue)
	if err != nil {
		return false
	}
	expectedScheme := "http"
	if r.TLS != nil {
		expectedScheme = "https"
	}
	return strings.EqualFold(origin.Scheme, expectedScheme) &&
		canonicalRemoteHost(origin.Host) == canonicalRemoteHost(r.Host) &&
		origin.Path == "" && origin.RawQuery == "" && origin.Fragment == ""
}

func (a *app) lanWebLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !lanWebRequestIsSameOrigin(r) {
		writeRemoteAPIError(w, http.StatusForbidden, "same_origin_required", "same-origin request required")
		return
	}
	contentType, ok := remoteSingleHeader(r.Header, "Content-Type")
	if !ok || !strings.HasPrefix(strings.ToLower(contentType), "application/json") {
		writeRemoteAPIError(w, http.StatusUnsupportedMediaType, "json_required", "application/json required")
		return
	}
	client := lanWebClientAddress(r)
	if a.lanWebAuth.locked(client) {
		w.Header().Set("Retry-After", "900")
		writeRemoteAPIError(w, http.StatusTooManyRequests, "login_locked", "too many failed attempts; try again later")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, lanWebMaxLoginBodyBytes+1))
	if err != nil || len(body) > lanWebMaxLoginBodyBytes {
		writeRemoteAPIError(w, http.StatusBadRequest, "invalid_body", "invalid login body")
		return
	}
	var payload struct {
		Password string `json:"password"`
	}
	if err := json.Unmarshal(body, &payload); err != nil || payload.Password == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "invalid_body", "password is required")
		return
	}
	token, ok := a.lanWebAuth.Login(payload.Password, client)
	if !ok {
		log.Printf("LAN web login rejected: client=%s", client)
		// Uniform delay keeps a wrong password indistinguishable from lockout timing.
		time.Sleep(400 * time.Millisecond)
		if a.lanWebAuth.locked(client) {
			w.Header().Set("Retry-After", "900")
			writeRemoteAPIError(w, http.StatusTooManyRequests, "login_locked", "too many failed attempts; try again later")
			return
		}
		writeRemoteAPIError(w, http.StatusUnauthorized, "invalid_password", "password is incorrect")
		return
	}
	log.Printf("LAN web login accepted: client=%s sessions=%d", client, a.lanWebAuth.ActiveSessions())
	http.SetCookie(w, a.lanWebSessionCookie(r, token, int(lanWebSessionTTL/time.Second)))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "next": "/remote/"})
}

func (a *app) lanWebSessionCookie(r *http.Request, value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name: lanWebSessionCookie, Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode,
	}
}

func (a *app) lanWebLogout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !lanWebRequestIsSameOrigin(r) {
		writeRemoteAPIError(w, http.StatusForbidden, "same_origin_required", "same-origin request required")
		return
	}
	if cookie, err := r.Cookie(lanWebSessionCookie); err == nil && cookie != nil {
		a.lanWebAuth.Revoke(cookie.Value)
	}
	http.SetCookie(w, a.lanWebSessionCookie(r, "", -1))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "login_url": lanWebLoginPagePath})
}

// lanWebAdvertisedURLs lists the addresses a phone on the same network can
// open, for the startup log and the local console.
func lanWebAdvertisedURLs(listen string, tls bool) []string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return nil
	}
	scheme := "http"
	if tls {
		scheme = "https"
	}
	var hosts []string
	if ip := net.ParseIP(host); host != "" && ip != nil && !ip.IsUnspecified() {
		hosts = append(hosts, host)
	} else {
		addresses, _ := net.InterfaceAddrs()
		for _, address := range addresses {
			ipNet, ok := address.(*net.IPNet)
			if !ok || ipNet.IP.To4() == nil || ipNet.IP.IsLoopback() || !ipNet.IP.IsPrivate() {
				continue
			}
			hosts = append(hosts, ipNet.IP.String())
		}
		if name, err := os.Hostname(); err == nil {
			name = strings.ToLower(strings.TrimSuffix(name, "."))
			if strings.HasSuffix(name, ".local") {
				hosts = append(hosts, name)
			}
		}
	}
	sort.Strings(hosts)
	urls := make([]string, 0, len(hosts))
	for _, candidate := range hosts {
		urls = append(urls, fmt.Sprintf("%s://%s/remote/", scheme, net.JoinHostPort(candidate, port)))
	}
	return urls
}
