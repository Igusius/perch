package main

// Usage/cost tab — reads month-to-date and today's spend from the OpenAI and
// Anthropic ORG-LEVEL cost APIs. Both need an ADMIN key (org-scoped, different
// from a normal API key); read server-side only and never sent to the browser.
// Results are cached and refreshed on start + on demand. No external module —
// just net/http + encoding/json.
//
// Provider specifics (verified against the docs):
//   OpenAI   GET /v1/organization/costs   — Bearer auth; amount.value is USD
//            dollars (float); daily buckets keyed by unix start_time.
//   Anthropic GET /v1/organizations/cost_report — x-api-key + anthropic-version;
//            amount is USD in CENTS as a decimal string; daily buckets keyed by
//            starting_at (RFC3339).
//
// NOTE: exact field names for the Anthropic cost_report weren't fully published
// at build time, so the parse is deliberately tolerant — validate against a
// real admin key and adjust if a total looks off.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var usageHTTP = &http.Client{Timeout: 20 * time.Second}

// ProviderUsage is one provider's spend summary for the UI.
type ProviderUsage struct {
	Name        string  `json:"name"`
	MonthToDate float64 `json:"month_to_date"`
	Today       float64 `json:"today"`
	Currency    string  `json:"currency"`
	Updated     int64   `json:"updated"`
	Error       string  `json:"error,omitempty"`
}

var (
	usageMu    sync.Mutex
	usageCache []ProviderUsage
	usageTime  int64
)

// usageConfigured reports whether at least one provider admin key is set.
func usageConfigured() bool {
	return os.Getenv("OPENAI_ADMIN_KEY") != "" || os.Getenv("ANTHROPIC_ADMIN_KEY") != ""
}

// parseAmount tolerantly reads a cost amount that may arrive as a JSON number
// (150) or a JSON string ("150") — Anthropic uses strings.
func parseAmount(raw json.RawMessage) float64 {
	f, _ := strconv.ParseFloat(strings.Trim(string(raw), `"`), 64)
	return f
}

// refreshUsage fetches every configured provider's spend and updates the cache.
func refreshUsage() []ProviderUsage {
	// Windows are computed in UTC to line up with how the providers bucket days.
	now := time.Now().UTC()
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)

	var result []ProviderUsage
	if os.Getenv("OPENAI_ADMIN_KEY") != "" {
		result = append(result, fetchOpenAI(monthStart, todayStart))
	}
	if os.Getenv("ANTHROPIC_ADMIN_KEY") != "" {
		result = append(result, fetchAnthropic(monthStart, todayStart, now))
	}

	usageMu.Lock()
	usageCache = result
	usageTime = time.Now().Unix()
	usageMu.Unlock()
	return result
}

// fetchOpenAI sums OpenAI's daily cost buckets from the start of the month.
func fetchOpenAI(monthStart, todayStart time.Time) ProviderUsage {
	p := ProviderUsage{Name: "OpenAI", Currency: "USD", Updated: time.Now().Unix()}
	url := fmt.Sprintf("https://api.openai.com/v1/organization/costs?start_time=%d&bucket_width=1d&limit=31",
		monthStart.Unix())
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+os.Getenv("OPENAI_ADMIN_KEY"))
	resp, err := usageHTTP.Do(req)
	if err != nil {
		p.Error = err.Error()
		return p
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		p.Error = fmt.Sprintf("HTTP %d (OPENAI_ADMIN_KEY must be an admin key: sk-admin-...)", resp.StatusCode)
		return p
	}
	var out struct {
		Data []struct {
			StartTime int64 `json:"start_time"`
			Results   []struct {
				Amount struct {
					Value float64 `json:"value"`
				} `json:"amount"`
			} `json:"results"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		p.Error = err.Error()
		return p
	}
	for _, b := range out.Data {
		var bucket float64
		for _, r := range b.Results {
			bucket += r.Amount.Value // OpenAI reports dollars
		}
		p.MonthToDate += bucket
		if b.StartTime >= todayStart.Unix() {
			p.Today += bucket
		}
	}
	return p
}

// fetchAnthropic sums Anthropic's daily cost buckets (cents) into dollars.
func fetchAnthropic(monthStart, todayStart, now time.Time) ProviderUsage {
	p := ProviderUsage{Name: "Anthropic", Currency: "USD", Updated: time.Now().Unix()}
	url := fmt.Sprintf("https://api.anthropic.com/v1/organizations/cost_report?starting_at=%s&ending_at=%s",
		monthStart.Format(time.RFC3339), now.Format(time.RFC3339))
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("x-api-key", os.Getenv("ANTHROPIC_ADMIN_KEY"))
	req.Header.Set("anthropic-version", "2023-06-01")
	resp, err := usageHTTP.Do(req)
	if err != nil {
		p.Error = err.Error()
		return p
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		p.Error = fmt.Sprintf("HTTP %d (ANTHROPIC_ADMIN_KEY must be an admin key: sk-ant-admin...)", resp.StatusCode)
		return p
	}
	var out struct {
		Data []struct {
			StartingAt string `json:"starting_at"`
			Results    []struct {
				Amount json.RawMessage `json:"amount"` // USD in cents, as a string
			} `json:"results"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		p.Error = err.Error()
		return p
	}
	for _, b := range out.Data {
		var cents float64
		for _, r := range b.Results {
			cents += parseAmount(r.Amount)
		}
		dollars := cents / 100.0
		p.MonthToDate += dollars
		if t, err := time.Parse(time.RFC3339, b.StartingAt); err == nil && !t.Before(todayStart) {
			p.Today += dollars
		}
	}
	return p
}

// handleUsage serves GET /api/usage — the cached provider spend (fetching once
// if the cache is empty). The keys themselves are never included.
func handleUsage(w http.ResponseWriter, _ *http.Request) {
	usageMu.Lock()
	cache, ts := usageCache, usageTime
	usageMu.Unlock()
	if cache == nil && usageConfigured() {
		cache = refreshUsage()
		ts = time.Now().Unix()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"providers": cache, "updated": ts, "configured": usageConfigured(),
	})
}

// handleUsageRefresh serves POST /api/usage/refresh — force a re-fetch.
func handleUsageRefresh(w http.ResponseWriter, _ *http.Request) {
	if !usageConfigured() {
		writeErr(w, http.StatusBadRequest, "set OPENAI_ADMIN_KEY and/or ANTHROPIC_ADMIN_KEY")
		return
	}
	res := refreshUsage()
	writeJSON(w, http.StatusOK, map[string]any{
		"providers": res, "updated": time.Now().Unix(), "configured": true,
	})
}
