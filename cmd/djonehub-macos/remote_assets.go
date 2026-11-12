package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// remoteAssetHandler serves embedded browser assets with content ETags so a
// phone on a cellular connection revalidates instead of re-downloading the
// PWA on every launch. HTML stays no-store (it names the current asset
// versions); versioned assets (?v=...) are immutable; everything else is
// revalidated with the ETag.
type remoteAssetHandler struct {
	etags map[string]string
	files http.Handler
}

func newRemoteAssetHandler(fsys fs.FS) http.Handler {
	handler := &remoteAssetHandler{etags: make(map[string]string), files: http.FileServer(http.FS(fsys))}
	_ = fs.WalkDir(fsys, ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil
		}
		data, readErr := fs.ReadFile(fsys, name)
		if readErr != nil {
			return nil
		}
		sum := sha256.Sum256(data)
		handler.etags[name] = `"` + hex.EncodeToString(sum[:16]) + `"`
		return nil
	})
	return handler
}

func (h *remoteAssetHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if name == "" {
		name = "index.html"
	}
	etag, ok := h.etags[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("ETag", etag)
	switch {
	case strings.HasSuffix(name, ".html"):
		w.Header().Set("Cache-Control", "no-store")
	case r.URL.Query().Get("v") != "":
		w.Header().Set("Cache-Control", "private, max-age=31536000, immutable")
	default:
		w.Header().Set("Cache-Control", "private, no-cache")
	}
	h.files.ServeHTTP(w, r)
}
