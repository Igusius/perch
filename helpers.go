package main

// Small shared helpers used across the HTTP handlers and state files. Keeping
// them in one place removes the response-boilerplate and path-resolution logic
// that was previously copy-pasted between handlers and between checks/alerts.

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
)

// writeJSON writes v as a JSON response with the given HTTP status code and the
// application/json content type — the header+status+encode trio every API
// handler needs, in one call.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeErr writes a JSON {"error": msg} body with the given status code — the
// uniform error shape the frontend expects.
func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// hasHTTPScheme reports whether s already begins with an http:// or https://
// scheme, so callers can decide whether to prepend a default one.
func hasHTTPScheme(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

// requestIsHTTPS reports whether the ORIGINAL browser request reached us over
// HTTPS. Behind a reverse proxy (nginx proxy manager) TLS terminates at the
// proxy and we see plain HTTP, so we trust the X-Forwarded-Proto it sets;
// r.TLS covers the rarer direct-HTTPS case. Used to gate the cookie Secure flag
// so local plain-HTTP development still keeps its session.
func requestIsHTTPS(r *http.Request) bool {
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		return strings.EqualFold(proto, "https")
	}
	return r.TLS != nil
}

// resolveStatePath picks where a small runtime state file lives: an explicit
// override in envKey wins; otherwise the writable /data volume (present in the
// Docker image) under dataName; otherwise localName next to the binary so a
// bare `go run .` persists too. Shared by the checks and alert state files.
func resolveStatePath(envKey, dataName, localName string) string {
	if p := os.Getenv(envKey); p != "" {
		return p
	}
	if info, err := os.Stat("/data"); err == nil && info.IsDir() {
		return dataName
	}
	return localName
}
