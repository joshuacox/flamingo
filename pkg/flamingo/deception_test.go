package flamingo

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHoneyfileManager(t *testing.T) {
	hm := NewHoneyfileManager()

	// Verify defaults
	expectedPaths := []string{
		"/.env",
		"/passwords.txt",
		"/.git/config",
		"/.aws/credentials",
		"/backup.sql",
		"/id_rsa",
	}

	for _, p := range expectedPaths {
		hf, ok := hm.Match(p)
		if !ok {
			t.Fatalf("expected default honeyfile %s to exist", p)
		}
		if hf.Content == "" {
			t.Fatalf("expected content for %s to be non-empty", p)
		}
	}

	// Verify path normalization (without leading slash)
	hf, ok := hm.Match(".env")
	if !ok || hf.Path != "/.env" {
		t.Fatalf("expected Match('.env') to resolve to '/.env'")
	}

	// Add custom honeyfile
	hm.AddHoneyfile(Honeyfile{
		Path:        "/admin/secrets.json",
		ContentType: "application/json",
		Content:     `{"api_key": "canary_test"}`,
		Description: "Admin test credentials",
	})

	custom, ok := hm.Match("/admin/secrets.json")
	if !ok {
		t.Fatalf("expected custom honeyfile to match")
	}
	if custom.ContentType != "application/json" {
		t.Errorf("expected application/json, got %s", custom.ContentType)
	}

	// Non-matching path
	_, ok = hm.Match("/nonexistent/file")
	if ok {
		t.Errorf("expected nonexistent path to not match")
	}
}

func TestServeHoneyfile(t *testing.T) {
	rw := NewRecordWriter()
	recordChan := make(chan map[string]string, 1)
	rw.OutputWriters = []OutputWriter{
		func(rec map[string]string) error {
			recordChan <- rec
			return nil
		},
	}

	// Test matching request
	req := httptest.NewRequest(http.MethodGet, "/.env", nil)
	req.RemoteAddr = "192.168.1.50:54321"
	req.Header.Set("User-Agent", "curl/8.0.1")
	w := httptest.NewRecorder()

	served := ServeHoneyfile(w, req, rw, "http")
	if !served {
		t.Fatalf("expected ServeHoneyfile to return true for /.env")
	}

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("expected Content-Type text/plain; charset=utf-8, got %s", ct)
	}

	select {
	case capturedRec := <-recordChan:
		if capturedRec["honeyfile"] != "/.env" {
			t.Errorf("expected honeyfile /.env, got %s", capturedRec["honeyfile"])
		}
		if capturedRec["_type"] != "honeyfile" {
			t.Errorf("expected _type honeyfile, got %s", capturedRec["_type"])
		}
		if capturedRec["_proto"] != "http" {
			t.Errorf("expected _proto http, got %s", capturedRec["_proto"])
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for honeyfile record")
	}

	// Test non-matching request
	req2 := httptest.NewRequest(http.MethodGet, "/index.html", nil)
	w2 := httptest.NewRecorder()
	served2 := ServeHoneyfile(w2, req2, rw, "http")
	if served2 {
		t.Errorf("expected ServeHoneyfile to return false for /index.html")
	}
}

func TestTarpitManager(t *testing.T) {
	// Threshold = 3 attempts in 100ms window, delay 10ms
	tm := NewTarpitManager(3, 100*time.Millisecond, 10*time.Millisecond)

	addr := "10.0.0.5:12345"

	// Attempts 1, 2, 3 should NOT trigger tarpit
	if tm.Track(addr) {
		t.Errorf("attempt 1 should not trigger tarpit")
	}
	if tm.Track(addr) {
		t.Errorf("attempt 2 should not trigger tarpit")
	}
	if tm.Track(addr) {
		t.Errorf("attempt 3 should not trigger tarpit")
	}

	// Attempt 4 (> threshold 3) MUST trigger tarpit
	if !tm.Track(addr) {
		t.Errorf("attempt 4 should trigger tarpit")
	}

	// Another IP should not be affected
	otherAddr := "10.0.0.6:54321"
	if tm.Track(otherAddr) {
		t.Errorf("different IP should not be throttled")
	}

	// Test disabled tarpit (threshold = 0)
	tm.SetThreshold(0)
	if tm.Track(addr) {
		t.Errorf("disabled tarpit should never trigger")
	}

	// Test SetDelay
	tm.SetDelay(5 * time.Millisecond)
	if tm.delay != 5*time.Millisecond {
		t.Errorf("expected delay 5ms, got %v", tm.delay)
	}
}
