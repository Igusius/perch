package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Authentication for public deployments.
//
// Design: a single access key lives in the ACCESS_KEY environment variable.
// When it (and GitHub login) is unset, auth is disabled entirely (local use).
// When set, every /api/* endpoint requires a valid session cookie EXCEPT the
// intentionally-public ones: /api/login, /api/logout, /api/health, /api/auth/info
// and the /api/auth/github/* OAuth flow. The session token is a minimal
// JWT-equivalent built with only the
// standard library: base64(expiry) + "." + base64(HMAC-SHA256(expiry)).
// It is stored in an HttpOnly cookie so page JavaScript can never read or
// leak it, expires after 24h, and is silently re-issued ("sliding refresh")
// whenever a request arrives with less than 4h of lifetime left.

const (
	cookieName    = "perch_session"
	tokenLifetime = 24 * time.Hour
	refreshWindow = 4 * time.Hour
)

// accessKey returns the configured login key ("" = key login disabled).
// ACCESS_KEY is the canonical name; PERCH_KEY is accepted as a fallback so
// the same .env works for a bare `go run .` and for the compose stack (which
// maps PERCH_KEY -> ACCESS_KEY itself).
func accessKey() string {
	if k := os.Getenv("ACCESS_KEY"); k != "" {
		return k
	}
	return os.Getenv("PERCH_KEY")
}

// authEnabled reports whether the deployment requires login — true when either
// an access key OR GitHub login is configured.
func authEnabled() bool { return accessKey() != "" || githubConfigured() }

// sessionSecretSource is the secret the session HMAC is derived from: the
// access key when set, otherwise the GitHub client secret (GitHub-only mode).
// When authEnabled() is true, one of them is always present.
func sessionSecretSource() string {
	if k := accessKey(); k != "" {
		return k
	}
	return os.Getenv("GITHUB_CLIENT_SECRET")
}

// tokenSecret derives the HMAC signing secret from the session secret source.
// Deriving (instead of generating a random secret at boot) keeps sessions valid
// across container restarts; the fixed prefix domain-separates it so the secret
// is never the raw key itself.
func tokenSecret() []byte {
	hash := sha256.Sum256([]byte("perch-token-v1:" + sessionSecretSource()))
	return hash[:]
}

// makeToken builds a signed session token that expires at the given time.
// Format: base64url(expiryUnix) + "." + base64url(HMAC-SHA256(expiryUnix)).
func makeToken(expiry time.Time) string {
	payload := []byte(strconv.FormatInt(expiry.Unix(), 10))
	mac := hmac.New(sha256.New, tokenSecret())
	mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// parseToken verifies a token's signature and expiry. It returns the expiry
// time and whether the token is currently valid. hmac.Equal is a
// constant-time comparison — a plain == would leak timing information an
// attacker could use to forge signatures byte by byte.
func parseToken(token string) (time.Time, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return time.Time{}, false
	}
	payload, payloadErr := base64.RawURLEncoding.DecodeString(parts[0])
	signature, signatureErr := base64.RawURLEncoding.DecodeString(parts[1])
	if payloadErr != nil || signatureErr != nil {
		return time.Time{}, false
	}
	mac := hmac.New(sha256.New, tokenSecret())
	mac.Write(payload)
	if !hmac.Equal(mac.Sum(nil), signature) {
		return time.Time{}, false
	}
	expiryUnix, err := strconv.ParseInt(string(payload), 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	expiry := time.Unix(expiryUnix, 0)
	return expiry, time.Now().Before(expiry)
}

// setSessionCookie issues a fresh 24h session cookie. HttpOnly keeps it out
// of reach of JavaScript; SameSite=Lax stops it being sent from other sites;
// Secure (set only when the request arrived over HTTPS) stops the browser ever
// sending it over plain HTTP. The HTTPS gate means local http:// dev keeps its
// session while a real deployment behind TLS gets the hardened cookie.
func setSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    makeToken(time.Now().Add(tokenLifetime)),
		Path:     "/",
		HttpOnly: true,
		Secure:   requestIsHTTPS(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(tokenLifetime.Seconds()),
	})
}

// requireAuth wraps an http.HandlerFunc with the session check — Go's
// middleware pattern: a function that takes a handler and returns a new
// handler. When auth is disabled it passes straight through. When the
// cookie is valid but expiring within 4h, a fresh cookie rides along on the
// response (the sliding refresh).
func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !authEnabled() {
			next(w, r)
			return
		}
		cookie, err := r.Cookie(cookieName)
		if err != nil {
			unauthorized(w)
			return
		}
		expiry, ok := parseToken(cookie.Value)
		if !ok {
			unauthorized(w)
			return
		}
		if time.Until(expiry) < refreshWindow {
			setSessionCookie(w, r)
		}
		next(w, r)
	}
}

// unauthorized sends the JSON 401 the frontend recognizes as "show the
// login overlay".
func unauthorized(w http.ResponseWriter) {
	writeErr(w, http.StatusUnauthorized, "unauthorized")
}

// loginAttempts tracks recent failed logins per client IP for rate limiting.
var (
	attemptsMu    sync.Mutex
	loginAttempts = map[string][]time.Time{}
)

// tooManyAttempts records one attempt for ip and reports whether the client
// exceeded 10 attempts in the last 5 minutes — a cheap in-memory brute-force
// brake (old entries are pruned as a side effect).
func tooManyAttempts(ip string) bool {
	attemptsMu.Lock()
	defer attemptsMu.Unlock()
	cutoff := time.Now().Add(-5 * time.Minute)
	recentAttempts := loginAttempts[ip][:0]
	for _, attemptTime := range loginAttempts[ip] {
		if attemptTime.After(cutoff) {
			recentAttempts = append(recentAttempts, attemptTime)
		}
	}
	recentAttempts = append(recentAttempts, time.Now())
	loginAttempts[ip] = recentAttempts
	return len(recentAttempts) > 10
}

// clientIP extracts the caller's IP, preferring X-Forwarded-For when a reverse
// proxy (nginx proxy manager on the VPS) sits in front.
//
// We take the LAST entry, not the first. nginx appends the real peer it saw
// (`$proxy_add_x_forwarded_for`), so a client that forges its own
// `X-Forwarded-For: 1.2.3.4` produces "1.2.3.4, <real-ip>" — the last hop is
// the address the proxy actually accepted the connection from, and the only
// one the client can't spoof. Trusting the first entry instead would let an
// attacker rotate a fake IP per request and slip past the login brake and the
// IP-ban list.
func clientIP(r *http.Request) string {
	if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
		hops := strings.Split(forwardedFor, ",")
		return strings.TrimSpace(hops[len(hops)-1])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// handleLogin implements POST /api/login {key}: rate-limit, compare the key
// in constant time, and on success set the session cookie. Both sides are
// hashed before subtle.ConstantTimeCompare so the comparison neither leaks
// timing nor the key lengths.
func handleLogin(w http.ResponseWriter, r *http.Request) {
	if !authEnabled() {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "auth": false})
		return
	}
	// Key login can be disabled while GitHub login is on (no ACCESS_KEY set).
	// Without this guard, an empty submitted key would match the empty
	// configured key and let anyone in.
	if accessKey() == "" {
		writeErr(w, http.StatusBadRequest, "access-key login is disabled; use GitHub")
		return
	}
	ip := clientIP(r)
	if tooManyAttempts(ip) {
		writeErr(w, http.StatusTooManyRequests, "too many attempts, wait 5 minutes")
		return
	}
	// a login body is tiny; cap it so the PUBLIC login endpoint can't be
	// used to stream a huge body into memory
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
	var req struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	providedKeyHash := sha256.Sum256([]byte(req.Key))
	configuredKeyHash := sha256.Sum256([]byte(accessKey()))
	if subtle.ConstantTimeCompare(providedKeyHash[:], configuredKeyHash[:]) != 1 {
		log.Printf("auth: failed login from %s", ip)
		time.Sleep(500 * time.Millisecond) // slow down guessing
		unauthorized(w)
		return
	}
	setSessionCookie(w, r)
	log.Printf("auth: successful login from %s", ip)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleLogout clears the session cookie (MaxAge -1 = delete immediately).
func handleLogout(w http.ResponseWriter, _ *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: "", Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`))
}
