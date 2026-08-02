package main

// Self-monitoring: perch watching itself. Two independent in-memory ring
// buffers, both bounded so they can never grow without limit:
//
//   1. selfLog     — a copy of perch's own log output (what normally only
//                    goes to stderr / `docker logs perch`).
//   2. accessLog   — one entry per HTTP request that reaches perch, filled
//                    by a middleware wrapping the whole router.
//
// Neither touches disk; both are read by small /api/self/* endpoints that the
// Logs tab renders.

import (
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// 1. perch's own logs
// ---------------------------------------------------------------------------

// selfLogBuffer is a thread-safe ring of the most recent log lines. It also
// satisfies io.Writer, which is the trick that lets the standard log package
// write straight into it (see captureOwnLogs).
type selfLogBuffer struct {
	mu    sync.Mutex
	lines []string // oldest first
	max   int      // cap; older lines are dropped past this
}

// selfLog keeps the last 500 log lines — plenty of recent history, trivial
// memory.
var selfLog = &selfLogBuffer{max: 500}

// Write makes selfLogBuffer an io.Writer. The log package hands us one whole
// message (with a trailing newline) per call; we strip that trailing newline
// and split on any interior ones so each stored entry is a clean single line.
// We always report the full byte count as written, per the io.Writer contract.
func (b *selfLogBuffer) Write(p []byte) (int, error) {
	// Remember the input length to return it unchanged.
	n := len(p)
	// Trim the trailing newline the logger adds, then split into lines.
	for _, line := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		b.append(line)
	}
	return n, nil
}

// append stores one line under the lock and trims the ring back to its cap by
// dropping the oldest entries.
func (b *selfLogBuffer) append(line string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	// Add the newest line at the end.
	b.lines = append(b.lines, line)
	// If we've grown past the cap, re-slice to keep only the newest `max`.
	if len(b.lines) > b.max {
		b.lines = b.lines[len(b.lines)-b.max:]
	}
}

// text returns every buffered line joined with newlines, oldest first — the
// same {"text": ...} shape the container-log endpoint returns, so the frontend
// can render perch's own logs with the exact same log-card code.
func (b *selfLogBuffer) text() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.Join(b.lines, "\n")
}

// captureOwnLogs redirects the standard logger to write to BOTH stderr (so
// `docker logs perch` keeps working exactly as before) and our in-memory
// ring. Call this once, first thing in main(), before anything logs — any line
// logged before this runs is simply not captured into the ring.
func captureOwnLogs() {
	log.SetOutput(io.MultiWriter(os.Stderr, selfLog))
}

// ---------------------------------------------------------------------------
// 2. incoming-request access log (perch's own traffic)
// ---------------------------------------------------------------------------

// AccessEntry is one request that hit perch itself: the in-app equivalent
// of an nginx access-log line, but for perch's own server.
type AccessEntry struct {
	Time      int64  `json:"time"`       // unix seconds when the request finished
	Method    string `json:"method"`     // GET, POST, ...
	Path      string `json:"path"`       // path + query string
	Status    int    `json:"status"`     // response status code we sent back
	IP        string `json:"ip"`         // client address (best-effort, see clientIP)
	LatencyMs int64  `json:"latency_ms"` // how long the handler took
}

// accessLogBuffer is a bounded ring of the most recent AccessEntry values.
type accessLogBuffer struct {
	mu      sync.Mutex
	entries []AccessEntry // oldest first
	max     int
}

// accessLog keeps the last 500 requests.
var accessLog = &accessLogBuffer{max: 500}

// add appends one entry under the lock and trims to the cap.
func (b *accessLogBuffer) add(e AccessEntry) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.entries = append(b.entries, e)
	if len(b.entries) > b.max {
		b.entries = b.entries[len(b.entries)-b.max:]
	}
}

// list returns a newest-first copy of the buffered entries (what the UI table
// wants at the top). Copying under the lock keeps callers race-free.
func (b *accessLogBuffer) list() []AccessEntry {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]AccessEntry, len(b.entries))
	// Walk the stored slice (oldest→newest) and place each entry at the
	// mirrored index so the result comes out newest→oldest.
	for i, e := range b.entries {
		out[len(b.entries)-1-i] = e
	}
	return out
}

// statusRecorder wraps an http.ResponseWriter so we can learn the status code
// after the handler runs — the standard ResponseWriter never exposes it.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

// WriteHeader records the code on its way through to the real writer.
func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// accessLogMiddleware records every request into accessLog: method, path,
// final status, client IP, and how long it took. It wraps the ENTIRE router
// (outermost, even outside the rate limiter) so it also captures requests that
// get rejected with 429 — useful for spotting abuse.
func accessLogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Start the stopwatch before the handler runs.
		start := time.Now()
		// Default the status to 200: if a handler writes a body without ever
		// calling WriteHeader, net/http sends 200, so that's the correct
		// assumption when we never observe an explicit code.
		rec := &statusRecorder{ResponseWriter: w, status: 200}
		// Run the actual handler chain.
		next.ServeHTTP(rec, r)
		// Record the completed request.
		accessLog.add(AccessEntry{
			Time:      time.Now().Unix(),
			Method:    r.Method,
			Path:      r.URL.RequestURI(),
			Status:    rec.status,
			IP:        clientIP(r),
			LatencyMs: time.Since(start).Milliseconds(),
		})
	})
}

// ---------------------------------------------------------------------------
// endpoints
// ---------------------------------------------------------------------------

// handleSelfLogs serves GET /api/self/logs — perch's own log output, in
// the same {"text": ...} shape as container logs so the frontend reuses the
// log-card renderer.
func handleSelfLogs(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"text": selfLog.text()})
}

// handleSelfRequests serves GET /api/self/requests — the recent requests that
// hit perch itself, newest first, for the access-log table.
func handleSelfRequests(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, accessLog.list())
}
