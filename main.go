package main

import (
	"embed"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// webFS embeds web/index.html INTO the compiled binary at build time via the
// //go:embed directive. That's why the final Docker image needs no web/
// directory, no nginx, no assets — the whole frontend travels inside the
// single executable.
//
//go:embed web/index.html
var webFS embed.FS

// version is the release this binary was built from. The Dockerfile and CI
// overwrite it at link time with -ldflags "-X main.version=v1.2.3"; a plain
// `go run .` leaves it as "dev".
var version = "dev"

// Overview is the entire dashboard payload — everything the frontend needs
// in one JSON document, returned by GET /api/overview.
type Overview struct {
	Machine       *MachineSnapshot `json:"machine"`
	GPUs          []GPU            `json:"gpus"`
	Containers    []Container      `json:"containers"`
	DockerError   string           `json:"docker_error,omitempty"`
	Checks        []CheckStatus    `json:"checks"`
	ChecksError   string           `json:"checks_error,omitempty"`
	Bans          []BanEntry       `json:"bans"`
	AuthEnabled   bool             `json:"auth_enabled"`
	AlertsEnabled bool             `json:"alerts_enabled"`
	Version       string           `json:"version"`
	Now           int64            `json:"now"`
}

// ipLimiter is the app-wide IP rate limiter; created in main, read by
// handleOverview (ban list) and handleUnban.
var ipLimiter *rateLimiter

// state is the latest collected Overview, shared between the collector
// goroutine (writer) and HTTP handlers (readers). sync.RWMutex allows many
// concurrent readers while giving the writer exclusive access — without it,
// simultaneous read+write would be a data race.
var (
	stateMu sync.RWMutex
	state   Overview
)

// collectLoop is the background collector goroutine, started once from
// main() with `go collectLoop()`. Every few seconds it gathers machine, GPU
// and container data (the expensive work), then swaps the results into the
// shared state under the write lock. Because collection happens here in the
// background, HTTP requests never wait for it — handlers just read the most
// recent snapshot and return instantly.
//
// The interval defaults to 15s (a good balance of freshness vs. load on the
// host and the Docker daemon); override it with COLLECT_INTERVAL_SECONDS. Trend
// samples are taken on a SEPARATE cadence (~every 15s) so the 240-point
// sparkline ring keeps spanning ~1h regardless of the loop interval.
func collectLoop() {
	interval := time.Duration(envInt("COLLECT_INTERVAL_SECONDS", 15, 1)) * time.Second
	// How many loop iterations make up ~15s of trend spacing (at least 1).
	trendEvery := int((15 * time.Second) / interval)
	if trendEvery < 1 {
		trendEvery = 1
	}
	for tick := 0; ; tick++ {
		machine := collectMachine()
		gpus := collectGPUs()
		containers, dockerErr := collectContainers()

		stateMu.Lock()
		state.Machine = machine
		state.GPUs = gpus
		state.Containers = containers
		state.DockerError = ""
		if dockerErr != nil {
			state.DockerError = dockerErr.Error()
		}
		stateMu.Unlock()

		// Sample the trend sparklines only every trendEvery-th cycle (keeps the
		// ~1h window), but evaluate alert rules every cycle so a DOWN/unhealthy
		// transition fires promptly. Both are no-ops when unconfigured.
		if tick%trendEvery == 0 {
			recordSample(machine)
		}
		evaluateAlerts(machine, containers, checkStatuses())

		time.Sleep(interval)
	}
}

// handleOverview serves GET /api/overview: copy the latest snapshot out
// under the read lock (a struct assignment is a cheap shallow copy), attach the
// live check statuses, ban list, auth/alert flags and the server time, and
// stream the whole thing as JSON straight into the response writer.
func handleOverview(w http.ResponseWriter, _ *http.Request) {
	stateMu.RLock()
	overview := state
	stateMu.RUnlock()
	overview.Checks = checkStatuses()
	overview.ChecksError = checksLoadError
	overview.Bans = ipLimiter.list()
	overview.AuthEnabled = authEnabled()
	overview.AlertsEnabled = alertsEnabled()
	overview.Version = version
	overview.Now = time.Now().Unix()
	writeJSON(w, http.StatusOK, overview)
}

// probeRequest is the JSON body the UI's probe box sends to POST /api/probe.
type probeRequest struct {
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

// probeResponse is what the probe returns to the UI: status line, timing,
// selected headers and a capped slice of the body.
type probeResponse struct {
	Status    int               `json:"status"`
	StatusStr string            `json:"status_str"`
	LatencyMs int64             `json:"latency_ms"`
	Headers   map[string]string `json:"headers"`
	Body      string            `json:"body"`
	Truncated bool              `json:"truncated"`
	Error     string            `json:"error,omitempty"`
}

// handleProbe implements the "curl from the browser" feature: it performs
// one HTTP request ON BEHALF OF the user and reports what happened.
//
// How it works: decode the target URL/method from the request body (a bare
// "host:port" gets http:// prepended), execute it with a 10s timeout, and
// measure the round trip. The response body is read through io.LimitReader
// capped at 8KB — enough to eyeball a health endpoint, impossible to blow up
// the UI with. Failures are returned as data (the Error field) rather than
// HTTP errors, so the frontend can render them like any other result.
func handleProbe(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	// cap the request body: without this a client could stream gigabytes
	// into the JSON decoder and exhaust memory (64KB is plenty for a probe)
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var req probeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(probeResponse{Error: "bad request: " + err.Error()})
		return
	}
	if !hasHTTPScheme(req.URL) {
		req.URL = "http://" + req.URL
	}
	if req.Method == "" {
		req.Method = "GET"
	}
	var bodyReader io.Reader
	if req.Body != "" {
		bodyReader = strings.NewReader(req.Body)
	}
	httpReq, err := http.NewRequest(strings.ToUpper(req.Method), req.URL, bodyReader)
	if err != nil {
		json.NewEncoder(w).Encode(probeResponse{Error: err.Error()})
		return
	}
	for headerName, headerValue := range req.Headers {
		httpReq.Header.Set(headerName, headerValue)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	start := time.Now()
	resp, err := client.Do(httpReq)
	latencyMs := time.Since(start).Milliseconds()
	if err != nil {
		json.NewEncoder(w).Encode(probeResponse{LatencyMs: latencyMs, Error: err.Error()})
		return
	}
	defer resp.Body.Close()

	const maxBodyBytes = 8 * 1024
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	truncated := false
	if len(body) > maxBodyBytes {
		body = body[:maxBodyBytes]
		truncated = true
	}
	headers := map[string]string{}
	for _, headerName := range []string{"Content-Type", "Content-Length", "Server", "Date"} {
		if headerValue := resp.Header.Get(headerName); headerValue != "" {
			headers[headerName] = headerValue
		}
	}
	json.NewEncoder(w).Encode(probeResponse{
		Status: resp.StatusCode, StatusStr: resp.Status,
		LatencyMs: latencyMs, Headers: headers,
		Body: string(body), Truncated: truncated,
	})
}

// handleUnban implements POST /api/unban — the dashboard's "remove" and
// "clear all" buttons for banned IPs. Body: {"ip":"1.2.3.4"} lifts one ban,
// {"all":true} lifts every ban. Auth-protected like all data endpoints.
func handleUnban(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
	var req struct {
		IP  string `json:"ip"`
		All bool   `json:"all"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || (!req.All && req.IP == "") {
		writeErr(w, http.StatusBadRequest, `need {"ip":"..."} or {"all":true}`)
		return
	}
	ip := req.IP
	if req.All {
		ip = ""
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "removed": ipLimiter.unban(ip)})
}

// main wires everything together and starts the server:
//  1. prime the CPU delta counters (see collectMachine),
//  2. load the saved health checks and start one goroutine per check,
//  3. start the background collector goroutine,
//  4. register the routes and serve. http.ListenAndServe itself spawns one
//     goroutine per incoming connection — concurrency is free, we never
//     write a thread pool.
//
// Route protection: data endpoints (overview, probe, logs) are wrapped in
// requireAuth — a no-op unless auth is enabled (ACCESS_KEY set OR GitHub login
// configured). The login/logout, health, /api/auth/info and OAuth routes stay
// public: login must be reachable to log in, and health is used by uptime
// monitors / the demo self-check, which have no cookies. The "POST /api/..."
// patterns (Go 1.22+) restrict those routes to POST; the "/" handler rejects
// other paths so unknown URLs get a real 404.
func main() {
	// Tee our own log output into an in-memory ring FIRST, so the Logs tab can
	// show perch's own logs. Must run before the first log line below.
	captureOwnLogs()
	// Load a local .env (for `go run .`) before anything reads the environment.
	loadDotEnv()
	log.Printf("perch %s starting", version)
	if authEnabled() {
		log.Println("auth: login required (access key and/or GitHub configured)")
	} else {
		log.Println("auth: no access key or GitHub login set — OPEN ACCESS (fine locally, set one on a VPS)")
	}
	collectMachine() // prime the cpu-percent delta counters
	loadChecks()
	loadAlertState() // restore the UI-saved webhook URL (if any)
	go collectLoop()
	// Warm the API-usage cache in the background so the Usage tab has data on
	// first view (no-op unless a provider admin key is set).
	go func() {
		if usageConfigured() {
			refreshUsage()
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/overview", requireAuth(handleOverview))
	mux.HandleFunc("POST /api/probe", requireAuth(handleProbe))
	mux.HandleFunc("/api/logs", requireAuth(handleContainerLogs))
	mux.HandleFunc("/api/inspect", requireAuth(handleInspect))
	mux.HandleFunc("/api/trends", requireAuth(handleTrends))
	mux.HandleFunc("GET /api/alerts", requireAuth(handleAlertsGet))
	mux.HandleFunc("POST /api/alerts", requireAuth(handleAlertsAdd))
	mux.HandleFunc("POST /api/alerts/remove", requireAuth(handleAlertsRemove))
	mux.HandleFunc("POST /api/alerts/test", requireAuth(handleAlertTest))
	mux.HandleFunc("/api/usage", requireAuth(handleUsage))
	mux.HandleFunc("POST /api/usage/refresh", requireAuth(handleUsageRefresh))
	mux.HandleFunc("/api/requests", requireAuth(handleRequests))
	mux.HandleFunc("/api/self/logs", requireAuth(handleSelfLogs))
	mux.HandleFunc("/api/self/requests", requireAuth(handleSelfRequests))
	mux.HandleFunc("POST /api/checks", requireAuth(handleAddCheck))
	mux.HandleFunc("POST /api/checks/remove", requireAuth(handleRemoveCheck))
	mux.HandleFunc("POST /api/unban", requireAuth(handleUnban))
	mux.HandleFunc("POST /api/login", handleLogin)
	mux.HandleFunc("POST /api/logout", handleLogout)
	// GitHub OAuth login (public: this IS the login flow). /api/auth/info tells
	// the overlay which sign-in options to show.
	mux.HandleFunc("/api/auth/info", handleAuthInfo)
	mux.HandleFunc("/api/auth/github/login", handleGithubLogin)
	mux.HandleFunc("/api/auth/github/callback", handleGithubCallback)
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		data, _ := webFS.ReadFile("web/index.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	})

	// Explicit server timeouts instead of http.ListenAndServe's defaults
	// (which are NONE). Without ReadHeaderTimeout a client can open a
	// connection and send headers one byte per minute forever (slowloris),
	// pinning a goroutine + file descriptor each time until the server
	// starves. Public-facing servers must always set these.
	//
	// The whole mux sits behind the IP rate limiter (see ratelimit.go):
	// spammy unauthenticated IPs get banned before any handler runs.
	// accessLogMiddleware wraps everything OUTERMOST so perch's own access
	// log records every request, including ones the limiter rejects with 429.
	ipLimiter = newRateLimiter()
	srv := &http.Server{
		Addr:              ":" + envOr("PORT", "3535"),
		Handler:           accessLogMiddleware(ipLimiter.middleware(mux)),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	log.Printf("perch listening on %s", srv.Addr)
	log.Fatal(srv.ListenAndServe())
}
