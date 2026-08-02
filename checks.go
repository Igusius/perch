package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// CheckConfig is one health check. The `yaml:"..."` tags map the
// lowercase YAML keys onto these exported struct fields when the file is
// parsed by yaml.Unmarshal.
type CheckConfig struct {
	ID           string            `yaml:"id" json:"id"` // stable id for UI remove; auto-assigned
	Name         string            `yaml:"name" json:"name"`
	URL          string            `yaml:"url" json:"url"`
	Method       string            `yaml:"method" json:"method"`
	Interval     int               `yaml:"interval" json:"interval"` // seconds
	Timeout      int               `yaml:"timeout" json:"timeout"`   // seconds
	ExpectStatus []int             `yaml:"expect_status" json:"expect_status"`
	Match        string            `yaml:"match" json:"match"` // optional body regex
	Headers      map[string]string `yaml:"headers" json:"headers"`
}

// CheckStatus is the latest observable result of one check — what the
// frontend renders as a green/red card.
type CheckStatus struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	URL         string  `json:"url"`
	Up          bool    `json:"up"`
	StatusCode  int     `json:"status_code"`
	LatencyMs   int64   `json:"latency_ms"`
	Error       string  `json:"error,omitempty"`
	LastChecked int64   `json:"last_checked"` // unix seconds
	UptimePct   float64 `json:"uptime_pct"`   // over recent history
	Interval    int     `json:"interval"`
}

// checkRunner is the live state of one scheduled check: its config, the
// compiled body regex, the latest status and a short up/down history.
// The mutex guards status+history because two goroutines touch them —
// the check's own loop writes, HTTP handlers read via checkStatuses.
type checkRunner struct {
	config    CheckConfig
	bodyRegex *regexp.Regexp
	stop      chan struct{} // closed to stop this check's loop goroutine
	mu        sync.Mutex
	status    CheckStatus
	history   []bool // ring of recent up/down, capped
}

var (
	checksMu sync.Mutex
	runners  []*checkRunner
	// checksLoadError explains why the dashboard shows zero checks: config
	// unreadable, unparseable, or one entry rejected. Written only by
	// loadChecks (which finishes before the HTTP server starts, same as
	// `runners`) and read by handleOverview, so the UI can say what is wrong
	// instead of the misleading "no checks configured".
	checksLoadError string
)

// newCheckID returns a short random hex id used to reference a check for
// removal from the UI. Falls back to a timestamp if the RNG ever fails.
func newCheckID() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("c%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// newRunner builds (but does not start) a checkRunner from a config: it fills
// in defaults, assigns an id if missing, and compiles the optional body regex.
// It returns an error for anything the UI should have caught (no URL, bad
// regex) so the add endpoint can report a reason.
func newRunner(config CheckConfig) (*checkRunner, error) {
	if strings.TrimSpace(config.URL) == "" {
		return nil, fmt.Errorf("url is required")
	}
	if config.Name == "" {
		config.Name = config.URL
	}
	if config.Method == "" {
		config.Method = "GET"
	}
	if config.Interval <= 0 {
		config.Interval = 15
	}
	if config.Timeout <= 0 {
		config.Timeout = 5
	}
	if config.ID == "" {
		config.ID = newCheckID()
	}
	runner := &checkRunner{config: config, stop: make(chan struct{})}
	runner.status = CheckStatus{ID: config.ID, Name: config.Name, URL: config.URL, Interval: config.Interval}
	if config.Match != "" {
		compiled, err := regexp.Compile(config.Match)
		if err != nil {
			return nil, fmt.Errorf("invalid match regex: %v", err)
		}
		runner.bodyRegex = compiled
	}
	return runner, nil
}

// startCheck registers a runner and launches its scheduler goroutine. It does
// NOT persist — the caller decides when to write the state file (once after the
// initial load, or per add).
func startCheck(config CheckConfig) (*checkRunner, error) {
	runner, err := newRunner(config)
	if err != nil {
		return nil, err
	}
	checksMu.Lock()
	runners = append(runners, runner)
	checksMu.Unlock()
	go runner.loop()
	return runner, nil
}

// addCheck creates a check at runtime (from the UI), persists the new set, and
// returns its initial status.
func addCheck(config CheckConfig) (CheckStatus, error) {
	config.ID = "" // never trust a client-supplied id; we assign one
	runner, err := startCheck(config)
	if err != nil {
		return CheckStatus{}, err
	}
	persistChecks()
	log.Printf("checks: added %q (%s)", runner.config.Name, runner.config.URL)
	runner.mu.Lock()
	status := runner.status
	runner.mu.Unlock()
	return status, nil
}

// removeCheck stops and drops the check with the given id, then persists.
// Returns false if no check had that id.
func removeCheck(id string) bool {
	checksMu.Lock()
	index := -1
	for i, runner := range runners {
		if runner.config.ID == id {
			index = i
			break
		}
	}
	if index == -1 {
		checksMu.Unlock()
		return false
	}
	runner := runners[index]
	runners = append(runners[:index], runners[index+1:]...)
	checksMu.Unlock()
	close(runner.stop) // signal its loop goroutine to exit
	persistChecks()
	log.Printf("checks: removed %q", runner.config.Name)
	return true
}

// loadChecks populates the running checks at startup. Precedence:
//  1. The UI-managed state file (checksStatePath) if it exists — authoritative.
//  2. Otherwise seed from the CHECKS_YAML env var, then write that seed to the
//     state file so future UI edits persist.
//
// With neither, we start with no checks at all: the dashboard shows an empty
// tile and you add them with "+ add check". That is the normal path — the env
// var exists for deployments that want checks declared in the stack itself.
func loadChecks() {
	if configs, ok := loadChecksState(); ok {
		for _, config := range configs {
			if _, err := startCheck(config); err != nil {
				log.Printf("checks: skipping %q from state: %v", config.Name, err)
			}
		}
		log.Printf("checks: %d loaded from %s (UI-managed)", len(runners), checksStatePath())
		return
	}

	inline := strings.TrimSpace(os.Getenv("CHECKS_YAML"))
	if inline == "" {
		return // nothing declared — add checks from the UI
	}
	var file struct {
		Checks []CheckConfig `yaml:"checks"`
	}
	if err := yaml.Unmarshal([]byte(inline), &file); err != nil {
		checksLoadError = fmt.Sprintf("cannot parse CHECKS_YAML: %v", err)
		log.Printf("checks: %s", checksLoadError)
		return
	}
	for _, config := range file.Checks {
		if config.URL == "" {
			continue
		}
		if _, err := startCheck(config); err != nil {
			checksLoadError = fmt.Sprintf("check %q skipped: %v", config.Name, err)
			log.Printf("checks: %s", checksLoadError)
		}
	}
	persistChecks() // write the seed so the UI becomes the source of truth
	log.Printf("checks: %d health checks seeded from CHECKS_YAML into %s", len(runners), checksStatePath())
}

// loop is the per-check scheduler goroutine: run once immediately, then on each
// ticker tick, until the check is removed (its stop channel is closed).
func (runner *checkRunner) loop() {
	runner.run()
	ticker := time.NewTicker(time.Duration(runner.config.Interval) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-runner.stop:
			return
		case <-ticker.C:
			runner.run()
		}
	}
}

// --- persistence: the UI-managed set lives in a small JSON file ------------

// checksStatePath returns where the UI-managed checks are stored (CHECKS_STATE_FILE
// override, else /data/checks.json on the volume, else a local file). Shares the
// resolution logic with the alert state file via resolveStatePath.
func checksStatePath() string {
	return resolveStatePath("CHECKS_STATE_FILE", "/data/checks.json", "checks.state.json")
}

// loadChecksState reads the UI-managed check set. ok=false means "no state file
// yet" (first run) — NOT an error — so the caller falls back to the YAML seed.
func loadChecksState() ([]CheckConfig, bool) {
	data, err := os.ReadFile(checksStatePath())
	if err != nil {
		return nil, false
	}
	var file struct {
		Checks []CheckConfig `json:"checks"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		log.Printf("checks: ignoring unreadable state file %s: %v", checksStatePath(), err)
		return nil, false
	}
	return file.Checks, true
}

// persistChecks writes the current set of checks to the state file so add/
// remove survive a restart. A write failure (e.g. no writable /data) is logged
// but never fatal — checks keep working in memory for the session.
func persistChecks() {
	checksMu.Lock()
	configs := make([]CheckConfig, 0, len(runners))
	for _, runner := range runners {
		configs = append(configs, runner.config)
	}
	checksMu.Unlock()
	data, err := json.MarshalIndent(struct {
		Checks []CheckConfig `json:"checks"`
	}{configs}, "", "  ")
	if err != nil {
		log.Printf("checks: cannot encode state: %v", err)
		return
	}
	// 0600: check configs can carry auth headers, so keep the file owner-only.
	if err := os.WriteFile(checksStatePath(), data, 0600); err != nil {
		log.Printf("checks: cannot write %s: %v", checksStatePath(), err)
	}
}

// handleAddCheck serves POST /api/checks — add a check from the UI. Body is a
// JSON CheckConfig (name/url/method/interval/timeout/expect_status/match/
// headers). Returns the new check's status, or 400 with a reason.
func handleAddCheck(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	var config CheckConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request: "+err.Error())
		return
	}
	status, err := addCheck(config)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, status)
}

// handleRemoveCheck serves POST /api/checks/remove — body {"id":"..."} drops
// one check.
func handleRemoveCheck(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		writeErr(w, http.StatusBadRequest, `need {"id":"..."}`)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "removed": removeCheck(req.ID)})
}

// run performs one probe of the target URL and records the outcome.
//
// How it works: build an http.Request with the configured method/headers,
// send it with a per-check timeout, and time it. The result is "up" when
// the status code is acceptable (the expect_status list if given, otherwise
// any 2xx/3xx) AND the body matches the optional regex (body reads are
// capped at 256KB with io.LimitReader so a huge response can't eat memory).
// Every exit path — even request-construction failure — goes through
// r.record so the history stays complete.
func (runner *checkRunner) run() {
	client := &http.Client{Timeout: time.Duration(runner.config.Timeout) * time.Second}
	req, err := http.NewRequest(runner.config.Method, runner.config.URL, nil)
	if err != nil {
		runner.record(false, 0, 0, err.Error())
		return
	}
	for headerName, headerValue := range runner.config.Headers {
		req.Header.Set(headerName, headerValue)
	}
	start := time.Now()
	resp, err := client.Do(req)
	latencyMs := time.Since(start).Milliseconds()
	if err != nil {
		runner.record(false, 0, latencyMs, err.Error())
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))

	isUp := false
	if len(runner.config.ExpectStatus) > 0 {
		for _, expectedCode := range runner.config.ExpectStatus {
			if resp.StatusCode == expectedCode {
				isUp = true
				break
			}
		}
	} else {
		isUp = resp.StatusCode >= 200 && resp.StatusCode < 400
	}
	errMsg := ""
	if !isUp {
		errMsg = fmt.Sprintf("unexpected status %d", resp.StatusCode)
	}
	if isUp && runner.bodyRegex != nil && !runner.bodyRegex.Match(body) {
		isUp = false
		errMsg = "body did not match pattern"
	}
	runner.record(isUp, resp.StatusCode, latencyMs, errMsg)
}

// record stores one probe result under the runner's mutex: it appends to the
// bounded history (last 100 results), recomputes the uptime percentage from
// it, and refreshes the public CheckStatus snapshot. defer r.mu.Unlock()
// guarantees the lock is released on every return path.
func (runner *checkRunner) record(isUp bool, statusCode int, latencyMs int64, errMsg string) {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	runner.history = append(runner.history, isUp)
	if len(runner.history) > 100 {
		runner.history = runner.history[1:]
	}
	upCount := 0
	for _, wasUp := range runner.history {
		if wasUp {
			upCount++
		}
	}
	runner.status.Up = isUp
	runner.status.StatusCode = statusCode
	runner.status.LatencyMs = latencyMs
	runner.status.Error = errMsg
	runner.status.LastChecked = time.Now().Unix()
	runner.status.UptimePct = 100 * float64(upCount) / float64(len(runner.history))
}

// checkStatuses copies out the current status of every check for the API
// response. Each runner is locked only for the instant its status is copied
// (CheckStatus is a plain value, so the copy is a real snapshot), then the
// list is sorted by name for a stable UI order.
func checkStatuses() []CheckStatus {
	// Snapshot the runners slice under checksMu (add/remove mutate it at
	// runtime now), then read each status under its own lock.
	checksMu.Lock()
	snapshot := make([]*checkRunner, len(runners))
	copy(snapshot, runners)
	checksMu.Unlock()
	statuses := make([]CheckStatus, 0, len(snapshot))
	for _, runner := range snapshot {
		runner.mu.Lock()
		statuses = append(statuses, runner.status)
		runner.mu.Unlock()
	}
	sort.Slice(statuses, func(i, j int) bool { return statuses[i].Name < statuses[j].Name })
	return statuses
}
