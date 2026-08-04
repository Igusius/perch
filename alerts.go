package main

// Alerting: when something crosses from good -> bad (a health check goes DOWN,
// a container turns unhealthy, a disk fills past a threshold), POST a message
// to a webhook. Fires only on TRANSITIONS, so you get one alert per event, not
// a message every cycle. The JSON body carries both "content" (Discord) and
// "text" (Slack / generic), so a single URL works for the common webhook
// targets.
//
// Any number of webhooks can be configured, and every alert goes to ALL of
// them. They come from two places, and the two are UNIONED (not either/or):
//   1. ALERT_WEBHOOK_URL — one URL, or several comma-separated. Declared by
//      whoever deploys the stack, and never removable from the browser.
//   2. URLs added from the Notifications card, persisted to a small state file
//      like health checks are. No restart needed.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	neturl "net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var alertHTTP = &http.Client{Timeout: 10 * time.Second}

// savedWebhooks holds the UI-managed webhook URLs. Guarded by webhookMu because
// the collect loop reads it while HTTP handlers may write it.
var (
	webhookMu     sync.RWMutex
	savedWebhooks []string
)

// envWebhooks returns the URLs declared in ALERT_WEBHOOK_URL (one, or several
// comma-separated).
func envWebhooks() []string { return splitList(os.Getenv("ALERT_WEBHOOK_URL")) }

// alertWebhookURLs returns every webhook an alert should be delivered to: the
// env-declared ones first, then the UI-added ones, with duplicates dropped so a
// URL present in both places is only messaged once. Empty = alerts off.
func alertWebhookURLs() []string {
	webhookMu.RLock()
	saved := append([]string(nil), savedWebhooks...)
	webhookMu.RUnlock()

	seen := map[string]bool{}
	var out []string
	for _, url := range append(envWebhooks(), saved...) {
		if url == "" || seen[url] {
			continue
		}
		seen[url] = true
		out = append(out, url)
	}
	return out
}

// alertsEnabled reports whether at least one webhook is configured.
func alertsEnabled() bool { return len(alertWebhookURLs()) > 0 }

var (
	alertMu       sync.Mutex
	prevCheckUp   = map[string]bool{} // check name -> was up
	prevUnhealthy = map[string]bool{} // container name -> was unhealthy
	prevDiskOver  = map[string]bool{} // mount -> was over threshold
	alertsPrimed  bool                // first pass only seeds state (no boot storm)
)

// diskThreshold is the percent-full at which a disk alerts (ALERT_DISK_PCT,
// default 90).
func diskThreshold() float64 {
	if v, err := strconv.ParseFloat(os.Getenv("ALERT_DISK_PCT"), 64); err == nil && v > 0 {
		return v
	}
	return 90
}

// evaluateAlerts compares the fresh snapshot against the previous one and fires
// a notification for each good<->bad transition. Safe to call every cycle.
func evaluateAlerts(m *MachineSnapshot, containers []Container, checks []CheckStatus) {
	if !alertsEnabled() {
		return
	}
	alertMu.Lock()
	defer alertMu.Unlock()

	// On the FIRST pass we only record current states — otherwise every
	// already-down check would alert the moment perch boots.
	seeding := !alertsPrimed

	// Health checks: UP <-> DOWN.
	for _, c := range checks {
		if c.LastChecked == 0 {
			continue // never probed yet
		}
		was, seen := prevCheckUp[c.Name]
		prevCheckUp[c.Name] = c.Up
		if seeding || !seen {
			continue
		}
		if was && !c.Up {
			notify(fmt.Sprintf("🔴 check DOWN: %s (%s)", c.Name, c.URL))
		} else if !was && c.Up {
			notify(fmt.Sprintf("🟢 check recovered: %s", c.Name))
		}
	}

	// Containers: healthy <-> unhealthy.
	for _, c := range containers {
		unhealthy := c.Health == "unhealthy"
		was, seen := prevUnhealthy[c.Name]
		prevUnhealthy[c.Name] = unhealthy
		if seeding || !seen {
			continue
		}
		if !was && unhealthy {
			notify(fmt.Sprintf("🔴 container unhealthy: %s", c.Name))
		} else if was && !unhealthy {
			notify(fmt.Sprintf("🟢 container healthy again: %s", c.Name))
		}
	}

	// Disks: crossing the fullness threshold.
	if m != nil {
		threshold := diskThreshold()
		for _, d := range m.Disks {
			over := d.UsedPct >= threshold
			was, seen := prevDiskOver[d.Mount]
			prevDiskOver[d.Mount] = over
			if seeding || !seen {
				continue
			}
			if !was && over {
				notify(fmt.Sprintf("🔴 disk %s at %.0f%% (over %.0f%%)", d.Mount, d.UsedPct, threshold))
			} else if was && !over {
				notify(fmt.Sprintf("🟢 disk %s back under %.0f%% (now %.0f%%)", d.Mount, threshold, d.UsedPct))
			}
		}
	}

	alertsPrimed = true
}

// notify delivers a message to every configured webhook, concurrently.
//
// It does not wait for the posts to finish. evaluateAlerts calls this while
// holding alertMu on the collect-loop goroutine, so a webhook that burns its
// full 10s timeout must not stall metric collection — let alone several of them
// one after another. Nothing consumes the result, so failures are just logged.
func notify(msg string) {
	for _, url := range alertWebhookURLs() {
		go func() {
			if err := notifyURL(url, msg); err != nil {
				log.Printf("alert: %s: %v", maskURL(url), err)
			}
		}()
	}
}

// notifyAll posts to every configured webhook and waits, returning one result
// per URL. Used by the test button, which has to tell the user which targets
// actually worked.
func notifyAll(msg string) []webhookResult {
	urls := alertWebhookURLs()
	results := make([]webhookResult, len(urls))
	var wg sync.WaitGroup
	for i, url := range urls {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = webhookResult{URL: maskURL(url), OK: true}
			if err := notifyURL(url, msg); err != nil {
				results[i].OK = false
				results[i].Error = err.Error()
			}
		}()
	}
	wg.Wait()
	return results
}

// webhookResult is the per-URL outcome of a test send.
type webhookResult struct {
	URL   string `json:"url"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// maskURL shortens a webhook URL to scheme://host/… so it can appear in logs
// and in the UI without leaking the token that the path or query carries.
func maskURL(rawURL string) string {
	u, err := neturl.Parse(rawURL)
	if err != nil || u.Host == "" {
		return "webhook"
	}
	if u.Path == "" && u.RawQuery == "" {
		return u.Scheme + "://" + u.Host
	}
	return u.Scheme + "://" + u.Host + "/…"
}

// notifyURL POSTs a message to a SPECIFIC url. It auto-detects the target:
// a Telegram bot URL gets Telegram's {chat_id,text} body, everything else
// (Discord / Slack / generic) gets {content,text}. Split out so the test
// button can probe a not-yet-saved URL.
func notifyURL(rawURL, msg string) error {
	req, err := buildNotifyRequest(rawURL, msg)
	if err != nil {
		return err
	}
	resp, err := alertHTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		// Surface a snippet of the response so the UI can show *why* it failed
		// (e.g. Telegram's "chat not found", Discord's "invalid webhook token").
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		detail := strings.TrimSpace(string(snippet))
		if detail != "" {
			return fmt.Errorf("webhook returned HTTP %d: %s", resp.StatusCode, detail)
		}
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// isTelegramURL reports whether a URL points at the Telegram Bot API.
func isTelegramURL(rawURL string) bool {
	u, err := neturl.Parse(rawURL)
	return err == nil && u.Host == "api.telegram.org"
}

// buildNotifyRequest constructs the right POST for the webhook flavor.
//
//	Telegram: https://api.telegram.org/bot<TOKEN>/sendMessage?chat_id=<ID>
//	          -> POST {chat_id, text} (chat_id pulled out of the query string).
//	Discord / Slack / generic: -> POST {content, text}.
func buildNotifyRequest(rawURL, msg string) (*http.Request, error) {
	if isTelegramURL(rawURL) {
		u, _ := neturl.Parse(rawURL)
		// Telegram wants the chat id in the payload; we let the user carry it in
		// the URL's query so the single-field UI still works.
		chatID := u.Query().Get("chat_id")
		if chatID == "" {
			return nil, fmt.Errorf("Telegram URL needs a ?chat_id=... (e.g. .../sendMessage?chat_id=123456789)")
		}
		// Rebuild the endpoint without the query — chat_id moves into the body.
		endpoint := u.Scheme + "://" + u.Host + u.Path
		body, _ := json.Marshal(map[string]string{"chat_id": chatID, "text": msg})
		req, err := http.NewRequest("POST", endpoint, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		return req, nil
	}
	// Discord / Slack / generic: both keys so either renders it.
	body, _ := json.Marshal(map[string]string{"content": msg, "text": msg})
	req, err := http.NewRequest("POST", rawURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

// --- persistence: the UI-saved webhook URL survives restarts -----------------

// alertStatePath mirrors checksStatePath (ALERT_STATE_FILE override, else
// /data/alert.json on the volume, else a local file) via the shared resolver.
func alertStatePath() string {
	return resolveStatePath("ALERT_STATE_FILE", "/data/alert.json", "alert.state.json")
}

// alertStateFile is the on-disk shape. WebhookURL is the pre-multi-webhook
// field, still read so an existing install keeps its notifications working
// after an upgrade; it is migrated into the list and never written again.
type alertStateFile struct {
	WebhookURLs []string `json:"webhook_urls"`
	WebhookURL  string   `json:"webhook_url,omitempty"` // legacy, read-only
}

// loadAlertState reads the saved webhook URLs on boot (no-op if none saved yet).
func loadAlertState() {
	data, err := os.ReadFile(alertStatePath())
	if err != nil {
		return // first run — nothing saved
	}
	var file alertStateFile
	if err := json.Unmarshal(data, &file); err != nil {
		log.Printf("alerts: ignoring unreadable state file %s: %v", alertStatePath(), err)
		return
	}

	urls := file.WebhookURLs
	migrated := false
	// Upgrade path: a file written before multi-webhook support carries a single
	// "webhook_url" and no list. Adopt it rather than silently dropping it.
	if len(urls) == 0 && strings.TrimSpace(file.WebhookURL) != "" {
		urls = []string{file.WebhookURL}
		migrated = true
	}

	var clean []string
	for _, u := range urls {
		if t := strings.TrimSpace(u); t != "" {
			clean = append(clean, t)
		}
	}

	webhookMu.Lock()
	savedWebhooks = clean
	webhookMu.Unlock()

	if len(clean) > 0 {
		log.Printf("alerts: %d webhook(s) loaded from %s (UI-managed)", len(clean), alertStatePath())
	}
	if migrated {
		persistAlertState() // rewrite in the new shape so the legacy key goes away
		log.Printf("alerts: migrated the single saved webhook into the new list format")
	}
}

// persistAlertState writes the saved webhook URLs. A write failure is logged but
// never fatal — they keep working in memory for the session.
func persistAlertState() {
	webhookMu.RLock()
	urls := append([]string{}, savedWebhooks...)
	webhookMu.RUnlock()
	data, _ := json.MarshalIndent(alertStateFile{WebhookURLs: urls}, "", "  ")
	if err := os.WriteFile(alertStatePath(), data, 0600); err != nil {
		log.Printf("alerts: cannot write %s: %v", alertStatePath(), err)
	}
}

// --- HTTP handlers -----------------------------------------------------------

// webhookView is one row of the Notifications list as the UI sees it.
type webhookView struct {
	URL       string `json:"url"`       // full for UI-added, masked for env-declared
	Source    string `json:"source"`    // "ui" | "env"
	Removable bool   `json:"removable"` // env-declared ones are config, not UI state
}

// handleAlertsGet serves GET /api/alerts — every configured webhook.
//
// UI-added URLs are echoed in full so the list is editable; env-declared ones
// are masked to scheme://host/… because ALERT_WEBHOOK_URL is a deployment
// secret that the browser was never given in the first place.
func handleAlertsGet(w http.ResponseWriter, _ *http.Request) {
	webhookMu.RLock()
	saved := append([]string(nil), savedWebhooks...)
	webhookMu.RUnlock()

	views := []webhookView{}
	for _, url := range envWebhooks() {
		views = append(views, webhookView{URL: maskURL(url), Source: "env"})
	}
	for _, url := range saved {
		views = append(views, webhookView{URL: url, Source: "ui", Removable: true})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":  alertsEnabled(),
		"webhooks": views,
	})
}

// handleAlertsAdd serves POST /api/alerts — add one webhook. Body:
// {"url":"https://..."}. Adding a URL that is already configured is a no-op
// rather than an error, so a double-click can't produce duplicate messages.
func handleAlertsAdd(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	url := strings.TrimSpace(body.URL)
	if url == "" {
		writeErr(w, http.StatusBadRequest, "enter a webhook URL")
		return
	}
	if !hasHTTPScheme(url) {
		writeErr(w, http.StatusBadRequest, "URL must start with http:// or https://")
		return
	}
	// Reject a Telegram URL with no chat_id here, where the message can reach
	// the person typing it, instead of failing silently at delivery time.
	if _, err := buildNotifyRequest(url, "validation"); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	webhookMu.Lock()
	exists := false
	for _, u := range savedWebhooks {
		if u == url {
			exists = true
			break
		}
	}
	if !exists {
		savedWebhooks = append(savedWebhooks, url)
	}
	webhookMu.Unlock()

	if !exists {
		persistAlertState()
		log.Printf("alerts: added webhook %s", maskURL(url))
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "added": !exists})
}

// handleAlertsRemove serves POST /api/alerts/remove — drop one UI-added
// webhook. Body: {"url":"https://..."}. Env-declared URLs cannot be removed
// here; they belong to whoever deployed the stack.
func handleAlertsRemove(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	target := strings.TrimSpace(body.URL)

	webhookMu.Lock()
	kept := make([]string, 0, len(savedWebhooks))
	removed := false
	for _, u := range savedWebhooks {
		if u == target {
			removed = true
			continue
		}
		kept = append(kept, u)
	}
	savedWebhooks = kept
	webhookMu.Unlock()

	if removed {
		persistAlertState()
		log.Printf("alerts: removed webhook %s", maskURL(target))
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "removed": removed})
}

// handleAlertTest serves POST /api/alerts/test — send a test message so the
// webhooks can be confirmed from the UI. With a "url" in the body that exact
// URL is probed, which lets you check one BEFORE adding it; otherwise every
// configured webhook is messaged and reported on individually.
func handleAlertTest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URL string `json:"url"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body)
	}
	const msg = "✅ test alert from perch — notifications are working"

	// Probing one specific (possibly unsaved) URL.
	if target := strings.TrimSpace(body.URL); target != "" {
		if !hasHTTPScheme(target) {
			writeErr(w, http.StatusBadRequest, "URL must start with http:// or https://")
			return
		}
		result := webhookResult{URL: maskURL(target), OK: true}
		if err := notifyURL(target, msg); err != nil {
			result.OK, result.Error = false, err.Error()
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": result.OK, "results": []webhookResult{result}})
		return
	}

	// Otherwise: everything that is configured.
	if !alertsEnabled() {
		writeErr(w, http.StatusBadRequest, "no webhooks yet — add one first")
		return
	}
	results := notifyAll(msg)
	allOK := true
	for _, res := range results {
		if !res.OK {
			allOK = false
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": allOK, "results": results})
}
