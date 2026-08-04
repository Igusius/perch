package main

// Tests for the alert webhook request builder — verifies each provider gets the
// body shape it expects, without touching the network.

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// useTempAlertState points the alert state file at a fresh temp path and clears
// the in-memory webhook list, so each test starts from a known state.
func useTempAlertState(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "alert.json")
	t.Setenv("ALERT_STATE_FILE", path)
	t.Setenv("ALERT_WEBHOOK_URL", "")
	webhookMu.Lock()
	savedWebhooks = nil
	webhookMu.Unlock()
	t.Cleanup(func() {
		webhookMu.Lock()
		savedWebhooks = nil
		webhookMu.Unlock()
	})
	return path
}

func TestLoadAlertState_MigratesLegacySingleURL(t *testing.T) {
	// A state file written before multi-webhook support carries "webhook_url".
	// Upgrading must keep that webhook working, not silently stop alerting.
	path := useTempAlertState(t)
	if err := os.WriteFile(path, []byte(`{"webhook_url":"https://example.com/hook"}`), 0600); err != nil {
		t.Fatal(err)
	}

	loadAlertState()

	got := alertWebhookURLs()
	if len(got) != 1 || got[0] != "https://example.com/hook" {
		t.Fatalf("legacy URL not adopted, got %v", got)
	}

	// The file should have been rewritten in the new shape, dropping the old key.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file map[string]any
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if _, stillThere := file["webhook_url"]; stillThere {
		t.Errorf("legacy webhook_url key should be gone after migration: %s", data)
	}
	if _, ok := file["webhook_urls"]; !ok {
		t.Errorf("expected webhook_urls in the rewritten file: %s", data)
	}
}

func TestAlertWebhookURLs_UnionsEnvAndUIWithoutDuplicates(t *testing.T) {
	// Every alert goes to all webhooks, so env and UI are unioned. A URL in both
	// places must appear once, or it would be messaged twice per event.
	useTempAlertState(t)
	t.Setenv("ALERT_WEBHOOK_URL", "https://a.example/1, https://both.example/x")
	webhookMu.Lock()
	savedWebhooks = []string{"https://b.example/2", "https://both.example/x"}
	webhookMu.Unlock()

	got := alertWebhookURLs()
	want := []string{"https://a.example/1", "https://both.example/x", "https://b.example/2"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("got %v, want %v", got, want)
	}
	if !alertsEnabled() {
		t.Error("alerts should be enabled when webhooks are configured")
	}
}

func TestAlertsEnabled_FalseWithNothingConfigured(t *testing.T) {
	useTempAlertState(t)
	if alertsEnabled() {
		t.Error("alerts must be off when no webhook is configured")
	}
}

func TestMaskURL_HidesTheToken(t *testing.T) {
	// Masked URLs reach logs and the browser, so the secret part must not survive.
	cases := []struct{ raw, secret string }{
		{"https://hooks.slack.com/services/T00/B11/SuperSecretToken", "SuperSecretToken"},
		{"https://api.telegram.org/bot123456:AAExampleToken/sendMessage?chat_id=99", "AAExampleToken"},
		{"https://discord.com/api/webhooks/1/dIsCoRdToKeN", "dIsCoRdToKeN"},
	}
	for _, c := range cases {
		masked := maskURL(c.raw)
		if strings.Contains(masked, c.secret) {
			t.Errorf("maskURL(%q) leaked the token: %q", c.raw, masked)
		}
		if !strings.Contains(masked, "://") {
			t.Errorf("maskURL(%q) should still name the host, got %q", c.raw, masked)
		}
	}
	if got := maskURL("not a url"); got != "webhook" {
		t.Errorf("unparseable URL should mask to a placeholder, got %q", got)
	}
}

func TestAlertsAddRemove(t *testing.T) {
	useTempAlertState(t)

	add := func(url string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/alerts", strings.NewReader(`{"url":"`+url+`"}`))
		handleAlertsAdd(rec, req)
		return rec.Code
	}
	remove := func(url string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/alerts/remove", strings.NewReader(`{"url":"`+url+`"}`))
		handleAlertsRemove(rec, req)
		return rec.Code
	}

	if code := add("https://hooks.slack.com/services/a/b/c"); code != 200 {
		t.Fatalf("add returned %d", code)
	}
	// Adding the same URL twice must not duplicate it — that would double every
	// future alert.
	if code := add("https://hooks.slack.com/services/a/b/c"); code != 200 {
		t.Fatalf("re-add returned %d", code)
	}
	if got := alertWebhookURLs(); len(got) != 1 {
		t.Fatalf("duplicate add created %d entries: %v", len(got), got)
	}

	if code := add("ftp://nope.example/x"); code != 400 {
		t.Errorf("non-http scheme should be rejected, got %d", code)
	}
	// A Telegram URL with no chat_id can never deliver, so it must be refused at
	// add time rather than failing quietly on the first real alert.
	if code := add("https://api.telegram.org/bot1:ABC/sendMessage"); code != 400 {
		t.Errorf("telegram URL without chat_id should be rejected, got %d", code)
	}

	if code := remove("https://hooks.slack.com/services/a/b/c"); code != 200 {
		t.Fatalf("remove returned %d", code)
	}
	if got := alertWebhookURLs(); len(got) != 0 {
		t.Errorf("expected no webhooks after removal, got %v", got)
	}
}

func TestAlertsRemove_CannotRemoveEnvWebhook(t *testing.T) {
	// Env-declared webhooks belong to whoever deployed the stack; the browser
	// must not be able to silence them.
	useTempAlertState(t)
	t.Setenv("ALERT_WEBHOOK_URL", "https://env.example/hook")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/alerts/remove", strings.NewReader(`{"url":"https://env.example/hook"}`))
	handleAlertsRemove(rec, req)

	if got := alertWebhookURLs(); len(got) != 1 || got[0] != "https://env.example/hook" {
		t.Errorf("env webhook should survive a remove call, got %v", got)
	}
}

// decodeBody reads and JSON-decodes a built request's body into a map.
func decodeBody(t *testing.T, b io.Reader) map[string]string {
	t.Helper()
	data, _ := io.ReadAll(b)
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("body is not JSON: %s", data)
	}
	return m
}

func TestBuildNotifyRequest_DiscordSlack(t *testing.T) {
	// A generic/Discord/Slack webhook must receive both content and text.
	req, err := buildNotifyRequest("https://discord.com/api/webhooks/1/abc", "hello")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.URL.String() != "https://discord.com/api/webhooks/1/abc" {
		t.Errorf("endpoint rewritten unexpectedly: %s", req.URL)
	}
	m := decodeBody(t, req.Body)
	if m["content"] != "hello" || m["text"] != "hello" {
		t.Errorf("want content+text=hello, got %v", m)
	}
	if _, isTelegram := m["chat_id"]; isTelegram {
		t.Errorf("non-telegram body should not carry chat_id: %v", m)
	}
}

func TestBuildNotifyRequest_Telegram(t *testing.T) {
	// A Telegram bot URL must be translated to {chat_id,text}, with chat_id
	// lifted out of the query string and the endpoint stripped of the query.
	req, err := buildNotifyRequest("https://api.telegram.org/bot123:ABC/sendMessage?chat_id=987654321", "ping")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.URL.String() != "https://api.telegram.org/bot123:ABC/sendMessage" {
		t.Errorf("chat_id should be removed from endpoint, got %s", req.URL)
	}
	m := decodeBody(t, req.Body)
	if m["chat_id"] != "987654321" {
		t.Errorf("want chat_id=987654321, got %q", m["chat_id"])
	}
	if m["text"] != "ping" {
		t.Errorf("want text=ping, got %q", m["text"])
	}
	if _, hasContent := m["content"]; hasContent {
		t.Errorf("telegram body must not carry Discord's content key: %v", m)
	}
}

func TestBuildNotifyRequest_TelegramMissingChatID(t *testing.T) {
	// Without a chat_id there is nowhere to deliver — must error, not silently
	// post a message that Telegram would reject.
	if _, err := buildNotifyRequest("https://api.telegram.org/bot123:ABC/sendMessage", "x"); err == nil {
		t.Fatal("expected an error when chat_id is missing")
	}
}

func TestIsTelegramURL(t *testing.T) {
	cases := map[string]bool{
		"https://api.telegram.org/bot1/sendMessage": true,
		"https://discord.com/api/webhooks/1/abc":    false,
		"https://hooks.slack.com/services/x/y/z":    false,
		"not a url":                                 false,
	}
	for url, want := range cases {
		if got := isTelegramURL(url); got != want {
			t.Errorf("isTelegramURL(%q) = %v, want %v", url, got, want)
		}
	}
}
