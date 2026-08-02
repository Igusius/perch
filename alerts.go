package main

// Alerting: when something crosses from good -> bad (a health check goes DOWN,
// a container turns unhealthy, a disk fills past a threshold), POST a message
// to a webhook. Fires only on TRANSITIONS, so you get one alert per event, not
// a message every cycle. The JSON body carries both "content" (Discord) and
// "text" (Slack / generic), so a single URL works for the common webhook
// targets.
//
// The webhook URL can be set two ways, checked in this order:
//   1. A UI-saved value, persisted to a small state file (like health checks).
//      Set/changed live from the Notifications card — no restart needed.
//   2. The ALERT_WEBHOOK_URL env var, used as a fallback when nothing is saved.
// This mirrors the checks model: env seeds a default, the UI takes over.

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

// savedWebhook holds the UI-managed webhook URL. Empty means "nothing saved —
// fall back to the env var". Guarded by webhookMu because the collect loop
// reads it while HTTP handlers may write it.
var (
	webhookMu    sync.RWMutex
	savedWebhook string
)

// alertWebhookURL returns the URL alerts should post to: the UI-saved value if
// present, otherwise the ALERT_WEBHOOK_URL env fallback. Empty = alerts off.
func alertWebhookURL() string {
	webhookMu.RLock()
	url := savedWebhook
	webhookMu.RUnlock()
	if url != "" {
		return url
	}
	return os.Getenv("ALERT_WEBHOOK_URL")
}

// webhookSource reports where the active URL came from, for the UI to show.
func webhookSource() string {
	webhookMu.RLock()
	saved := savedWebhook
	webhookMu.RUnlock()
	if saved != "" {
		return "ui"
	}
	if os.Getenv("ALERT_WEBHOOK_URL") != "" {
		return "env"
	}
	return "none"
}

// alertsEnabled reports whether any webhook (UI-saved or env) is configured.
func alertsEnabled() bool { return alertWebhookURL() != "" }

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

// notify POSTs a message to the currently-active webhook (UI-saved or env).
func notify(msg string) error {
	url := alertWebhookURL()
	if url == "" {
		return fmt.Errorf("no webhook configured")
	}
	return notifyURL(url, msg)
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
		log.Printf("alert: webhook post failed: %v", err)
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		// Surface a snippet of the response so the UI can show *why* it failed
		// (e.g. Telegram's "chat not found", Discord's "invalid webhook token").
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		detail := strings.TrimSpace(string(snippet))
		log.Printf("alert: webhook returned HTTP %d: %s", resp.StatusCode, detail)
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

// loadAlertState reads the saved webhook URL on boot (no-op if none saved yet).
func loadAlertState() {
	data, err := os.ReadFile(alertStatePath())
	if err != nil {
		return // first run — nothing saved
	}
	var file struct {
		WebhookURL string `json:"webhook_url"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		log.Printf("alerts: ignoring unreadable state file %s: %v", alertStatePath(), err)
		return
	}
	webhookMu.Lock()
	savedWebhook = strings.TrimSpace(file.WebhookURL)
	webhookMu.Unlock()
	if savedWebhook != "" {
		log.Printf("alerts: webhook loaded from %s (UI-managed)", alertStatePath())
	}
}

// persistAlertState writes the saved webhook URL. A write failure is logged but
// never fatal — the URL keeps working in memory for the session.
func persistAlertState() {
	webhookMu.RLock()
	url := savedWebhook
	webhookMu.RUnlock()
	data, _ := json.MarshalIndent(struct {
		WebhookURL string `json:"webhook_url"`
	}{url}, "", "  ")
	if err := os.WriteFile(alertStatePath(), data, 0600); err != nil {
		log.Printf("alerts: cannot write %s: %v", alertStatePath(), err)
	}
}

// --- HTTP handlers -----------------------------------------------------------

// handleAlertsGet serves GET /api/alerts — current webhook status for the UI.
// The URL itself is returned so the field can be pre-filled, but only when it
// came from the UI (an env-provided secret is never echoed to the browser).
func handleAlertsGet(w http.ResponseWriter, _ *http.Request) {
	src := webhookSource()
	webhookMu.RLock()
	saved := savedWebhook
	webhookMu.RUnlock()
	shown := ""
	if src == "ui" {
		shown = saved // safe to echo: the user typed it here
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": alertsEnabled(),
		"source":  src, // "ui" | "env" | "none"
		"url":     shown,
	})
}

// handleAlertsSave serves POST /api/alerts/save — set (or clear) the webhook
// URL from the UI and persist it. Body: {"url":"https://..."}. An empty url
// clears the saved value and falls back to the env var.
func handleAlertsSave(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	url := strings.TrimSpace(body.URL)
	// Reject anything that isn't an http(s) URL so we don't persist garbage.
	if url != "" && !hasHTTPScheme(url) {
		writeErr(w, http.StatusBadRequest, "URL must start with http:// or https://")
		return
	}
	webhookMu.Lock()
	savedWebhook = url
	webhookMu.Unlock()
	persistAlertState()
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": alertsEnabled(),
		"source":  webhookSource(),
		"url":     url,
	})
}

// handleAlertTest serves POST /api/alerts/test — fire a test message so the
// webhook can be confirmed from the UI. If the body carries a "url", that exact
// URL is probed (lets you test BEFORE saving); otherwise the active webhook is
// used.
func handleAlertTest(w http.ResponseWriter, r *http.Request) {
	// Optional {"url": "..."} lets the UI test an unsaved value.
	var body struct {
		URL string `json:"url"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body)
	}
	target := strings.TrimSpace(body.URL)
	if target == "" {
		target = alertWebhookURL() // fall back to the active webhook
	}
	if target == "" {
		writeErr(w, http.StatusBadRequest, "no webhook URL — enter or save one first")
		return
	}
	if !hasHTTPScheme(target) {
		writeErr(w, http.StatusBadRequest, "URL must start with http:// or https://")
		return
	}
	if err := notifyURL(target, "✅ test alert from perch — notifications are working"); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
