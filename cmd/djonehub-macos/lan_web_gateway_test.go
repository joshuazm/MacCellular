package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testLANWebPassword = "correct-horse-battery-staple"
	testLANWebHost     = "192.168.3.200:7579"
)

func writeLANWebPasswordFile(t *testing.T, password string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "lan-web-password")
	if err := os.WriteFile(path, []byte(password+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func newLANWebTestApp(t *testing.T, control bool) (*app, http.Handler) {
	t.Helper()
	startup, err := parseLANWebStartupConfig(lanWebFlagConfig{
		Listen: "0.0.0.0:7579", PasswordFile: writeLANWebPasswordFile(t, testLANWebPassword),
		Control: control, SessionsFile: filepath.Join(t.TempDir(), "lan-web", "sessions.json"),
	})
	if err != nil {
		t.Fatalf("parse LAN web config: %v", err)
	}
	instance := newDemoApp()
	if err := instance.initializeSMSStore(filepath.Join(t.TempDir(), "sms")); err != nil {
		t.Fatal(err)
	}
	if err := instance.configureLANWeb(startup, filepath.Join(t.TempDir(), "operations.jsonl")); err != nil {
		t.Fatalf("configure LAN web: %v", err)
	}
	t.Cleanup(func() {
		_ = instance.remoteLedger.Close()
		instance.closeSMSStore()
	})
	return instance, instance.lanWebRoutes()
}

func lanWebTestRequest(method, target, host string, cookie *http.Cookie) *http.Request {
	request := httptest.NewRequest(method, target, nil)
	request.Host = host
	request.RemoteAddr = "192.168.3.42:51000"
	if cookie != nil {
		request.AddCookie(cookie)
	}
	return request
}

func lanWebLoginRequest(host, password string) *http.Request {
	body := strings.NewReader(`{"password":` + strconvQuote(password) + `}`)
	request := httptest.NewRequest(http.MethodPost, lanWebLoginAPIPath, body)
	request.Host = host
	request.RemoteAddr = "192.168.3.42:51000"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://"+host)
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	return request
}

func strconvQuote(value string) string {
	data, _ := json.Marshal(value)
	return string(data)
}

func lanWebLogin(t *testing.T, handler http.Handler, host, password string) (*httptest.ResponseRecorder, *http.Cookie) {
	t.Helper()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, lanWebLoginRequest(host, password))
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == lanWebSessionCookie && cookie.Value != "" {
			return response, cookie
		}
	}
	return response, nil
}

func TestParseLANWebStartupConfigValidation(t *testing.T) {
	if startup, err := parseLANWebStartupConfig(lanWebFlagConfig{}); err != nil || startup != nil {
		t.Fatalf("blank flags must keep LAN web disabled: %v %+v", err, startup)
	}
	password := writeLANWebPasswordFile(t, testLANWebPassword)
	cases := map[string]lanWebFlagConfig{
		"missing listen":       {PasswordFile: password},
		"missing password":     {Listen: "0.0.0.0:7579"},
		"relative password":    {Listen: "0.0.0.0:7579", PasswordFile: "relative/file"},
		"port zero":            {Listen: "0.0.0.0:0", PasswordFile: password},
		"hostname listen":      {Listen: "mac.local:7579", PasswordFile: password},
		"tls cert without key": {Listen: "0.0.0.0:7579", PasswordFile: password, TLSCertFile: "/tmp/cert.pem"},
		"tls relative key":     {Listen: "0.0.0.0:7579", PasswordFile: password, TLSCertFile: "/tmp/cert.pem", TLSKeyFile: "key.pem"},
		"host with path":       {Listen: "0.0.0.0:7579", PasswordFile: password, Hosts: "mac/home"},
		"short password":       {Listen: "0.0.0.0:7579", PasswordFile: writeLANWebPasswordFile(t, "short")},
		"multi-line password":  {Listen: "0.0.0.0:7579", PasswordFile: writeLANWebPasswordFile(t, "line-one-long\nline-two")},
		"relative sessions":    {Listen: "0.0.0.0:7579", PasswordFile: password, SessionsFile: "sessions.json"},
		"wrong password mode":  {Listen: "0.0.0.0:7579", PasswordFile: writeWorldReadable(t, testLANWebPassword)},
	}
	for name, flags := range cases {
		if _, err := parseLANWebStartupConfig(flags); err == nil {
			t.Errorf("%s: expected configuration error", name)
		}
	}
	startup, err := parseLANWebStartupConfig(lanWebFlagConfig{
		Listen: ":7579", PasswordFile: password, Hosts: "Mac-Mini.home.example., phone-box",
		SessionsFile: filepath.Join(t.TempDir(), "sessions.json"),
	})
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if _, ok := startup.ExtraHosts["mac-mini.home.example"]; !ok {
		t.Fatalf("extra hosts were not canonicalised: %+v", startup.ExtraHosts)
	}
	if _, ok := startup.ExtraHosts["phone-box"]; !ok {
		t.Fatalf("extra hosts dropped a name: %+v", startup.ExtraHosts)
	}
	if startup.TLS() {
		t.Fatal("TLS must stay off without certificate flags")
	}
}

func writeWorldReadable(t *testing.T, password string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "lan-web-password-0644")
	if err := os.WriteFile(path, []byte(password+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLANWebHostAllowedRejectsPublicNames(t *testing.T) {
	extra := map[string]struct{}{"phone.home.example": {}}
	allowed := []string{
		"192.168.3.200:7579", "10.0.0.5", "172.16.4.9:7579", "[fd12::1]:7579", "[fe80::1]:7579",
		"127.0.0.1:7579", "localhost:7579", "miaodemac-mini.local:7579", "mac.home.arpa", "mac-mini",
		"gateway.lan", "Phone.Home.Example:7579",
	}
	for _, host := range allowed {
		if !lanWebHostAllowed(host, extra) {
			t.Errorf("host %q should be allowed", host)
		}
	}
	denied := []string{
		"", "8.8.8.8:7579", "203.0.113.4", "[2001:db8::1]:7579", "attacker.example.com:7579",
		"phone.example.com", "192.168.3.200/path", "100.64.0.1",
	}
	for _, host := range denied {
		if lanWebHostAllowed(host, extra) {
			t.Errorf("host %q should be denied", host)
		}
	}
}

func TestLANWebLoginIssuesSessionCookieAndAuthorizesPWA(t *testing.T) {
	instance, handler := newLANWebTestApp(t, true)

	// Unauthenticated navigation goes to the login page; API calls get a
	// machine-readable 401 instead.
	navigation := lanWebTestRequest(http.MethodGet, "/remote/", testLANWebHost, nil)
	navigation.Header.Set("Sec-Fetch-Mode", "navigate")
	navigation.Header.Set("Accept", "text/html")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, navigation)
	if response.Code != http.StatusSeeOther || !strings.HasPrefix(response.Header().Get("Location"), lanWebLoginPagePath+"?next=") {
		t.Fatalf("navigation without session: status=%d location=%q", response.Code, response.Header().Get("Location"))
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, lanWebTestRequest(http.MethodGet, "/api/remote/v1/session", testLANWebHost, nil))
	if response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), `"login_required"`) {
		t.Fatalf("API without session: status=%d body=%s", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unauthenticated API response must be no-store: %q", response.Header().Get("Cache-Control"))
	}

	// The login page itself is reachable without a session and carries the
	// hardening headers.
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, lanWebTestRequest(http.MethodGet, lanWebLoginPagePath, testLANWebHost, nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "访问密码") {
		t.Fatalf("login page: status=%d body=%.80s", response.Code, response.Body.String())
	}
	if response.Header().Get("Content-Security-Policy") == "" || response.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("login page lacks hardening headers: %+v", response.Header())
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, lanWebTestRequest(http.MethodGet, "/lan/login.js", testLANWebHost, nil))
	if response.Code != http.StatusOK || response.Header().Get("ETag") == "" {
		t.Fatalf("login asset: status=%d etag=%q", response.Code, response.Header().Get("ETag"))
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, lanWebTestRequest(http.MethodGet, "/lan/icon.svg", testLANWebHost, nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Header().Get("Content-Type"), "svg") {
		t.Fatalf("login icon: status=%d type=%q", response.Code, response.Header().Get("Content-Type"))
	}

	// Wrong password: 401 with no cookie.
	wrong, cookie := lanWebLogin(t, handler, testLANWebHost, "not-the-password")
	if wrong.Code != http.StatusUnauthorized || cookie != nil {
		t.Fatalf("wrong password: status=%d cookie=%v", wrong.Code, cookie)
	}

	// Correct password: HttpOnly cookie, session persisted.
	ok, cookie := lanWebLogin(t, handler, testLANWebHost, testLANWebPassword)
	if ok.Code != http.StatusOK || cookie == nil {
		t.Fatalf("login: status=%d body=%s", ok.Code, ok.Body.String())
	}
	if !cookie.HttpOnly || cookie.Path != "/" || cookie.Secure || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("cookie attributes: %+v", cookie)
	}
	if instance.lanWebAuth.ActiveSessions() != 1 {
		t.Fatalf("active sessions = %d", instance.lanWebAuth.ActiveSessions())
	}
	if data, err := os.ReadFile(instance.lanWeb.SessionsFile); err != nil || strings.Contains(string(data), cookie.Value) {
		t.Fatalf("session store must persist only hashed tokens: err=%v contains_raw=%t", err, strings.Contains(string(data), cookie.Value))
	}

	// Session endpoint reports the LAN transport and SMS-only capabilities.
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, lanWebTestRequest(http.MethodGet, "/api/remote/v1/session", testLANWebHost, cookie))
	if response.Code != http.StatusOK {
		t.Fatalf("session with cookie: status=%d body=%s", response.Code, response.Body.String())
	}
	var session struct {
		Transport string   `json:"transport"`
		SMSOnly   bool     `json:"sms_only"`
		Actions   []string `json:"actions"`
		Identity  string   `json:"identity"`
		CSRF      string   `json:"csrf_token"`
		Media     string   `json:"media"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	if session.Transport != "lan" || !session.SMSOnly || session.Media != "disabled" ||
		!strings.HasPrefix(session.Identity, "lan-") || session.CSRF == "" {
		t.Fatalf("unexpected LAN session: %+v", session)
	}
	if strings.Join(session.Actions, ",") != "sms.read,sms.send,status.read" {
		t.Fatalf("unexpected LAN actions: %v", session.Actions)
	}

	// The PWA shell and a versioned asset are served with cache validators.
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, lanWebTestRequest(http.MethodGet, "/remote/", testLANWebHost, cookie))
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("PWA shell: status=%d cache=%q", response.Code, response.Header().Get("Cache-Control"))
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, lanWebTestRequest(http.MethodGet, "/remote/app.js?v=test", testLANWebHost, cookie))
	if response.Code != http.StatusOK || !strings.Contains(response.Header().Get("Cache-Control"), "immutable") || response.Header().Get("ETag") == "" {
		t.Fatalf("versioned asset: status=%d cache=%q etag=%q", response.Code, response.Header().Get("Cache-Control"), response.Header().Get("ETag"))
	}
	revalidate := lanWebTestRequest(http.MethodGet, "/remote/app.js?v=test", testLANWebHost, cookie)
	revalidate.Header.Set("If-None-Match", response.Header().Get("ETag"))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, revalidate)
	if response.Code != http.StatusNotModified {
		t.Fatalf("ETag revalidation: status=%d", response.Code)
	}

	// Mutations over plain HTTP need a same-origin http:// Origin plus CSRF.
	send := httptest.NewRequest(http.MethodPost, "/api/remote/v1/sms/send", strings.NewReader(`{"phone":"+8613800000000","message":"hello"}`))
	send.Host = testLANWebHost
	send.RemoteAddr = "192.168.3.42:51000"
	send.AddCookie(cookie)
	send.Header.Set("Content-Type", "application/json")
	send.Header.Set("Origin", "http://"+testLANWebHost)
	send.Header.Set("Sec-Fetch-Site", "same-origin")
	send.Header.Set("Idempotency-Key", "lan-test-send-1")
	send.Header.Set("X-MacCellular-CSRF", session.CSRF)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, send)
	if response.Code == http.StatusForbidden {
		t.Fatalf("same-origin http mutation was rejected: body=%s", response.Body.String())
	}
	send = httptest.NewRequest(http.MethodPost, "/api/remote/v1/sms/send", strings.NewReader(`{"phone":"+8613800000000","message":"hello"}`))
	send.Host = testLANWebHost
	send.AddCookie(cookie)
	send.Header.Set("Content-Type", "application/json")
	send.Header.Set("Origin", "http://evil.example.com")
	send.Header.Set("Sec-Fetch-Site", "cross-site")
	send.Header.Set("X-MacCellular-CSRF", session.CSRF)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, send)
	if response.Code != http.StatusForbidden {
		t.Fatalf("cross-site mutation must be rejected: status=%d", response.Code)
	}

	// A public hostname pointing at the LAN address (DNS rebinding) is refused
	// even with a valid cookie.
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, lanWebTestRequest(http.MethodGet, "/api/remote/v1/session", "attacker.example.com:7579", cookie))
	if response.Code != http.StatusForbidden {
		t.Fatalf("public host must be refused: status=%d", response.Code)
	}

	// Routes outside the SMS subset are not present on this listener.
	for _, path := range []string{"/api/remote/v1/calls/dial", "/api/remote/v1/media/offers", "/api/status", "/api/at", "/api/native/x"} {
		request := lanWebTestRequest(http.MethodPost, path, testLANWebHost, cookie)
		request.Header.Set("Content-Type", "application/json")
		response = httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Errorf("%s: status=%d, want 404", path, response.Code)
		}
	}

	// Logout revokes the session and clears the cookie.
	logout := httptest.NewRequest(http.MethodPost, lanWebLogoutAPIPath, strings.NewReader("{}"))
	logout.Host = testLANWebHost
	logout.AddCookie(cookie)
	logout.Header.Set("Content-Type", "application/json")
	logout.Header.Set("Origin", "http://"+testLANWebHost)
	logout.Header.Set("Sec-Fetch-Site", "same-origin")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, logout)
	if response.Code != http.StatusOK || instance.lanWebAuth.ActiveSessions() != 0 {
		t.Fatalf("logout: status=%d sessions=%d", response.Code, instance.lanWebAuth.ActiveSessions())
	}
	cleared := false
	for _, c := range response.Result().Cookies() {
		if c.Name == lanWebSessionCookie && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("logout did not clear the session cookie")
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, lanWebTestRequest(http.MethodGet, "/api/remote/v1/session", testLANWebHost, cookie))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("revoked session still accepted: status=%d", response.Code)
	}
}

func TestLANWebReadOnlyWithoutControl(t *testing.T) {
	_, handler := newLANWebTestApp(t, false)
	_, cookie := lanWebLogin(t, handler, testLANWebHost, testLANWebPassword)
	if cookie == nil {
		t.Fatal("login failed")
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, lanWebTestRequest(http.MethodGet, "/api/remote/v1/session", testLANWebHost, cookie))
	if strings.Contains(response.Body.String(), `"sms.send"`) || !strings.Contains(response.Body.String(), `"remote_control":false`) {
		t.Fatalf("read-only session advertised control: %s", response.Body.String())
	}
	send := httptest.NewRequest(http.MethodPost, "/api/remote/v1/sms/send", strings.NewReader(`{"phone":"1","message":"x"}`))
	send.Host = testLANWebHost
	send.AddCookie(cookie)
	send.Header.Set("Content-Type", "application/json")
	send.Header.Set("Origin", "http://"+testLANWebHost)
	send.Header.Set("Sec-Fetch-Site", "same-origin")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, send)
	if response.Code != http.StatusForbidden {
		t.Fatalf("send without control: status=%d", response.Code)
	}
}

func TestLANWebLoginLocksAfterRepeatedFailures(t *testing.T) {
	instance, handler := newLANWebTestApp(t, false)
	now := time.Now()
	instance.lanWebAuth.now = func() time.Time { return now }
	for attempt := 0; attempt < lanWebMaxFailuresPerIP; attempt++ {
		response, _ := lanWebLogin(t, handler, testLANWebHost, "wrong-password-"+string(rune('a'+attempt)))
		if response.Code != http.StatusUnauthorized && response.Code != http.StatusTooManyRequests {
			t.Fatalf("attempt %d: status=%d", attempt, response.Code)
		}
	}
	response, cookie := lanWebLogin(t, handler, testLANWebHost, testLANWebPassword)
	if response.Code != http.StatusTooManyRequests || cookie != nil {
		t.Fatalf("locked client must be refused even with the right password: status=%d", response.Code)
	}
	// A different client is unaffected by the per-address lock.
	other := lanWebLoginRequest(testLANWebHost, testLANWebPassword)
	other.RemoteAddr = "192.168.3.77:40000"
	otherResponse := httptest.NewRecorder()
	handler.ServeHTTP(otherResponse, other)
	if otherResponse.Code != http.StatusOK {
		t.Fatalf("other client: status=%d body=%s", otherResponse.Code, otherResponse.Body.String())
	}
	// The lock expires with the failure window.
	instance.lanWebAuth.now = func() time.Time { return now.Add(lanWebFailureWindow + time.Second) }
	response, cookie = lanWebLogin(t, handler, testLANWebHost, testLANWebPassword)
	if response.Code != http.StatusOK || cookie == nil {
		t.Fatalf("lock did not expire: status=%d", response.Code)
	}
}

func TestLANWebLoginRejectsCrossSiteAndNonJSON(t *testing.T) {
	_, handler := newLANWebTestApp(t, false)
	request := lanWebLoginRequest(testLANWebHost, testLANWebPassword)
	request.Header.Set("Origin", "http://evil.example.com")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("foreign origin login: status=%d", response.Code)
	}
	request = lanWebLoginRequest(testLANWebHost, testLANWebPassword)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("form login: status=%d", response.Code)
	}
	// Non-browser clients without Origin are accepted (browsers always send it).
	request = lanWebLoginRequest(testLANWebHost, testLANWebPassword)
	request.Header.Del("Origin")
	request.Header.Del("Sec-Fetch-Site")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("origin-less login: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestLANWebSessionsSurviveRestart(t *testing.T) {
	sessions := filepath.Join(t.TempDir(), "lan-web", "sessions.json")
	password := writeLANWebPasswordFile(t, testLANWebPassword)
	build := func() (*app, http.Handler) {
		startup, err := parseLANWebStartupConfig(lanWebFlagConfig{
			Listen: "0.0.0.0:7579", PasswordFile: password, SessionsFile: sessions,
		})
		if err != nil {
			t.Fatal(err)
		}
		instance := newDemoApp()
		if err := instance.initializeSMSStore(filepath.Join(t.TempDir(), "sms")); err != nil {
			t.Fatal(err)
		}
		if err := instance.configureLANWeb(startup, filepath.Join(t.TempDir(), "operations.jsonl")); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = instance.remoteLedger.Close()
			instance.closeSMSStore()
		})
		return instance, instance.lanWebRoutes()
	}
	_, first := build()
	_, cookie := lanWebLogin(t, first, testLANWebHost, testLANWebPassword)
	if cookie == nil {
		t.Fatal("login failed")
	}
	info, err := os.Stat(sessions)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("session store permissions: err=%v mode=%v", err, info.Mode())
	}
	_, second := build()
	response := httptest.NewRecorder()
	second.ServeHTTP(response, lanWebTestRequest(http.MethodGet, "/api/remote/v1/session", testLANWebHost, cookie))
	if response.Code != http.StatusOK {
		t.Fatalf("session did not survive restart: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestLANWebGatewayPathSubset(t *testing.T) {
	for _, path := range []string{"/", "/remote", "/remote/", "/remote/app.js", "/api/remote/v1/session", "/api/remote/v1/snapshot", "/api/remote/v1/sms/sync", "/api/remote/v1/sms/send", "/api/remote/v1/sms/refresh"} {
		if !isLANWebGatewayPath(path) {
			t.Errorf("%s should be allowed", path)
		}
	}
	for _, path := range []string{"/api/remote/v1/calls/dial", "/api/remote/v1/calls/answer", "/api/remote/v1/media/offers", "/api/remote/v2/voice/snapshot", "/api/status", "/api/at", "/api/native/", "/api/remote/v1/recordings", lanWebLoginAPIPath} {
		if isLANWebGatewayPath(path) {
			t.Errorf("%s must not be allowed through the authenticated subtree", path)
		}
	}
}

func TestLANWebAdvertisedURLsUseExplicitListenAddress(t *testing.T) {
	urls := lanWebAdvertisedURLs("192.168.3.200:7579", true)
	if len(urls) != 1 || urls[0] != "https://192.168.3.200:7579/remote/" {
		t.Fatalf("unexpected URLs: %v", urls)
	}
	if lanWebAdvertisedURLs("garbage", false) != nil {
		t.Fatal("invalid listen address must produce no URLs")
	}
}
