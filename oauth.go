package main

// GitHub OAuth login — an alternative to the access key. When GITHUB_CLIENT_ID
// and GITHUB_CLIENT_SECRET are set, the login overlay offers "Sign in with
// GitHub". A user is admitted ONLY if their GitHub username or a VERIFIED email
// is on the allowlist (GITHUB_ALLOWED_USERS / GITHUB_ALLOWED_EMAILS). On
// success we issue the very same signed session cookie the access-key login
// uses (see setSessionCookie), so the rest of the app needs no changes.
//
// The flow is the standard OAuth 2.0 Authorization Code exchange:
//   /api/auth/github/login    -> redirect the browser to GitHub to authorize
//   /api/auth/github/callback -> GitHub redirects back with a code; we swap it
//                                for a token, read the profile, check the
//                                allowlist, and set the session cookie.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// oauthHTTP is a dedicated client with a timeout for the GitHub round trips
// (never reuse the probe client; these are our own trusted calls).
var oauthHTTP = &http.Client{Timeout: 10 * time.Second}

// oauthStateCookie holds a random anti-CSRF value for the in-flight round trip.
const oauthStateCookie = "perch_oauth_state"

// githubConfigured reports whether GitHub login is available (both halves of
// the OAuth app credential are present).
func githubConfigured() bool {
	return os.Getenv("GITHUB_CLIENT_ID") != "" && os.Getenv("GITHUB_CLIENT_SECRET") != ""
}

// randomToken returns 16 random bytes hex-encoded, for the OAuth state value.
func randomToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("s%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// redirectBase reconstructs the externally-visible origin (scheme://host),
// honouring the reverse proxy's X-Forwarded-* headers so the callback URL we
// build matches what the browser — and GitHub — actually use.
func redirectBase(r *http.Request) string {
	scheme := "http"
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	} else if r.TLS != nil {
		scheme = "https"
	}
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	return scheme + "://" + host
}

// githubRedirectURI is the callback URL GitHub sends the user back to. It must
// match (or be under) the callback registered in the GitHub OAuth App.
func githubRedirectURI(r *http.Request) string {
	return redirectBase(r) + "/api/auth/github/callback"
}

// handleGithubLogin starts the flow: stash a random state in a short-lived
// cookie (to defend against CSRF) and redirect to GitHub's authorize page.
func handleGithubLogin(w http.ResponseWriter, r *http.Request) {
	if !githubConfigured() {
		http.Error(w, "github login not configured", http.StatusNotFound)
		return
	}
	state := randomToken()
	http.SetCookie(w, &http.Cookie{
		Name: oauthStateCookie, Value: state, Path: "/",
		HttpOnly: true, Secure: requestIsHTTPS(r), SameSite: http.SameSiteLaxMode, MaxAge: 600, // 10 minutes
	})
	authURL := "https://github.com/login/oauth/authorize?" + url.Values{
		"client_id":    {os.Getenv("GITHUB_CLIENT_ID")},
		"redirect_uri": {githubRedirectURI(r)},
		"scope":        {"read:user user:email"}, // read the profile + emails only
		"state":        {state},
	}.Encode()
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleGithubCallback completes the flow: verify state, exchange the code for
// a token, read the profile + verified emails, check the allowlist, and — on
// success — issue the session cookie and land on the dashboard.
func handleGithubCallback(w http.ResponseWriter, r *http.Request) {
	// 1. Anti-CSRF: the state we set must come back unchanged.
	stateCookie, err := r.Cookie(oauthStateCookie)
	if err != nil || stateCookie.Value == "" || stateCookie.Value != r.URL.Query().Get("state") {
		githubFail(w, "invalid or expired sign-in state, please try again")
		return
	}
	// Consume the state cookie so it can't be replayed.
	http.SetCookie(w, &http.Cookie{Name: oauthStateCookie, Value: "", Path: "/", MaxAge: -1})

	code := r.URL.Query().Get("code")
	if code == "" {
		githubFail(w, "no authorization code returned by GitHub")
		return
	}

	// 2. Exchange the code for an access token.
	token, err := githubExchange(code, githubRedirectURI(r))
	if err != nil {
		githubFail(w, "token exchange failed: "+err.Error())
		return
	}

	// 3. Read who they are.
	login, verifiedEmails, err := githubUser(token)
	if err != nil {
		githubFail(w, "could not read your GitHub profile: "+err.Error())
		return
	}

	// 4. Allowlist check — fail closed.
	if !githubAllowed(login, verifiedEmails) {
		log.Printf("auth: github user %q denied (not on allowlist)", login)
		githubFail(w, "the GitHub account @"+login+" is not on this instance's allowlist")
		return
	}

	// 5. Success: same session cookie as the key login, then to the dashboard.
	setSessionCookie(w, r)
	log.Printf("auth: github login ok for %q", login)
	http.Redirect(w, r, "/", http.StatusFound)
}

// githubExchange swaps an authorization code for an access token. We ask for a
// JSON response (GitHub defaults to form-encoded) to keep parsing simple.
func githubExchange(code, redirectURI string) (string, error) {
	form := url.Values{
		"client_id":     {os.Getenv("GITHUB_CLIENT_ID")},
		"client_secret": {os.Getenv("GITHUB_CLIENT_SECRET")},
		"code":          {code},
		"redirect_uri":  {redirectURI},
	}
	req, _ := http.NewRequest("POST", "https://github.com/login/oauth/access_token",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := oauthHTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error_description"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&out); err != nil {
		return "", err
	}
	if out.AccessToken == "" {
		if out.Error != "" {
			return "", fmt.Errorf("%s", out.Error)
		}
		return "", fmt.Errorf("no access token returned")
	}
	return out.AccessToken, nil
}

// githubAPIGet performs one authenticated GET against the GitHub REST API and
// decodes the JSON into target.
func githubAPIGet(token, endpoint string, target any) error {
	req, _ := http.NewRequest("GET", endpoint, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := oauthHTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("github api %s: HTTP %d", endpoint, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 256*1024)).Decode(target)
}

// githubUser returns the authenticated user's login and their VERIFIED emails
// (lowercased). Reading emails is best-effort: if it fails we still return the
// login so username-based allowlisting works.
func githubUser(token string) (string, []string, error) {
	var profile struct {
		Login string `json:"login"`
	}
	if err := githubAPIGet(token, "https://api.github.com/user", &profile); err != nil {
		return "", nil, err
	}
	var emailList []struct {
		Email    string `json:"email"`
		Verified bool   `json:"verified"`
	}
	// Ignore the error: without the email scope this simply yields none.
	_ = githubAPIGet(token, "https://api.github.com/user/emails", &emailList)
	var verified []string
	for _, e := range emailList {
		if e.Verified {
			verified = append(verified, strings.ToLower(e.Email))
		}
	}
	return profile.Login, verified, nil
}

// githubAllowed reports whether this GitHub identity is permitted. A user
// passes if their login is in GITHUB_ALLOWED_USERS OR one of their verified
// emails is in GITHUB_ALLOWED_EMAILS. With neither list set, NOBODY passes —
// fail closed so a half-configured instance can't be logged into by anyone.
func githubAllowed(login string, verifiedEmails []string) bool {
	login = strings.ToLower(login)
	for _, u := range splitList(os.Getenv("GITHUB_ALLOWED_USERS")) {
		if strings.ToLower(u) == login {
			return true
		}
	}
	allowedEmails := splitList(os.Getenv("GITHUB_ALLOWED_EMAILS"))
	for _, have := range verifiedEmails {
		for _, want := range allowedEmails {
			if strings.ToLower(want) == have {
				return true
			}
		}
	}
	return false
}

// splitList parses a comma-separated env value into trimmed, non-empty items.
func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if t := strings.TrimSpace(part); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// githubFail renders a small HTML error page (the callback is a full-page
// redirect, not a fetch, so a JSON body wouldn't be seen).
func githubFail(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, `<!doctype html><meta charset="utf-8">
<body style="font-family:system-ui,sans-serif;background:#0d0d0d;color:#fff;padding:40px;line-height:1.5">
  <h2 style="margin:0 0 8px">GitHub sign-in failed</h2>
  <p style="color:#c3c2b7">%s</p>
  <p><a href="/" style="color:#3987e5">&larr; back to perch</a></p>
</body>`, html.EscapeString(msg))
}

// handleAuthInfo is a PUBLIC endpoint the login overlay calls to decide which
// sign-in options to show (access key box, GitHub button, or both).
func handleAuthInfo(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{
		"enabled": authEnabled(),
		"key":     accessKey() != "",
		"github":  githubConfigured(),
	})
}
