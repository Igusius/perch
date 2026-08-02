package main

// Tests for the alert webhook request builder — verifies each provider gets the
// body shape it expects, without touching the network.

import (
	"encoding/json"
	"io"
	"testing"
)

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
