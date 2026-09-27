package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSplunkWriter(t *testing.T) {
	var receivedBody map[string]any
	var authHeader string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &receivedBody)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"text":"Success","code":0}`))
	}))
	defer ts.Close()

	writer, cleaner, err := getSplunkWriter("splunk://" + ts.URL + "?token=SECRET123&index=security")
	if err != nil {
		t.Fatalf("getSplunkWriter error: %v", err)
	}
	defer cleaner()

	testRec := map[string]string{
		"_host":    "10.0.0.1",
		"_proto":   "ssh",
		"_type":    "credential",
		"username": "root",
		"password": "Password1!",
	}

	if err := writer(testRec); err != nil {
		t.Fatalf("writer error: %v", err)
	}

	if authHeader != "Splunk SECRET123" {
		t.Errorf("expected 'Splunk SECRET123', got '%s'", authHeader)
	}
	if receivedBody["index"] != "security" {
		t.Errorf("expected index security, got %v", receivedBody["index"])
	}
	if receivedBody["sourcetype"] != "flamingo:honeypot" {
		t.Errorf("expected sourcetype flamingo:honeypot, got %v", receivedBody["sourcetype"])
	}
}

func TestDiscordWriter(t *testing.T) {
	var receivedBody map[string]any

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &receivedBody)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	writer, cleaner, err := getDiscordWriter("discord://" + ts.URL)
	if err != nil {
		t.Fatalf("getDiscordWriter error: %v", err)
	}
	defer cleaner()

	testRec := map[string]string{
		"_host":     "10.0.0.2",
		"_proto":    "http",
		"_type":     "honeyfile",
		"honeyfile": "/.env",
		"username":  "admin",
	}

	if err := writer(testRec); err != nil {
		t.Fatalf("writer error: %v", err)
	}

	embeds, ok := receivedBody["embeds"].([]any)
	if !ok || len(embeds) == 0 {
		t.Fatalf("expected embeds array in discord payload")
	}
	embed := embeds[0].(map[string]any)
	if !strings.Contains(embed["title"].(string), "Flamingo Alert") {
		t.Errorf("unexpected embed title: %v", embed["title"])
	}
}

func TestTeamsWriter(t *testing.T) {
	var receivedBody map[string]any

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &receivedBody)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`1`))
	}))
	defer ts.Close()

	writer, cleaner, err := getTeamsWriter("teams://" + ts.URL)
	if err != nil {
		t.Fatalf("getTeamsWriter error: %v", err)
	}
	defer cleaner()

	testRec := map[string]string{
		"_host":    "10.0.0.3",
		"_proto":   "smb",
		"_type":    "credential",
		"username": "Administrator",
	}

	if err := writer(testRec); err != nil {
		t.Fatalf("writer error: %v", err)
	}

	if receivedBody["@type"] != "MessageCard" {
		t.Errorf("expected MessageCard, got %v", receivedBody["@type"])
	}
}
