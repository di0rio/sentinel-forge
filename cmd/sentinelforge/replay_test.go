package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/di0rio/sentinel-forge/internal/engine"
	"github.com/di0rio/sentinel-forge/internal/parser"
	"github.com/di0rio/sentinel-forge/internal/rule"
)

func TestReadEventsRejectsInvalidEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.json")
	data := `[
  {"id": "b", "timestamp": "2026-09-26T14:00:02Z", "source": "auth", "type": "authentication_failure"},
  {"id": "a", "timestamp": "2026-09-26T14:00:01Z", "source": "auth", "type": "authentication_failure"},
  {"id": "missing-type", "timestamp": "2026-09-26T14:00:03Z", "source": "auth"},
  {"id": "unknown-field", "ts": "2026-09-26T14:00:04Z", "source": "auth", "type": "x"}
]`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}

	events, failed, err := readEvents(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].ID != "a" || events[1].ID != "b" {
		t.Fatalf("want valid events [a b] sorted by timestamp, got %+v", events)
	}
	if len(failed) != 2 {
		t.Fatalf("want 2 rejected events, got %d: %v", len(failed), failed)
	}
}

func TestLoadEventsLogFormats(t *testing.T) {
	dir := t.TempDir()
	sshd := filepath.Join(dir, "auth.log")
	data := "Oct  3 14:32:12 host sshd[1]: Failed password for root from 203.0.113.45 port 22 ssh2\n" +
		"Oct  3 14:32:11 host sshd[1]: Accepted password for alice from 198.51.100.7 port 22 ssh2\n" +
		"Oct  3 14:32:13 host CRON[2]: session opened\n" +
		strings.Repeat("x", parser.MaxLineBytes+1) + "\n"
	if err := os.WriteFile(sshd, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}

	events, failed, skipped, err := loadEvents(sshd, formatSSHD, 2026)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].Type != "authentication_success" || events[0].Timestamp.Year() != 2026 {
		t.Fatalf("want 2 events sorted by timestamp dated 2026, got %+v", events)
	}
	if skipped != 1 || len(failed) != 1 {
		t.Fatalf("want 1 skipped and 1 failed line, got skipped=%d failed=%v", skipped, failed)
	}
}

func TestLoadEventsRejectsBadOptions(t *testing.T) {
	tests := []struct {
		name    string
		format  string
		year    int
		wantErr string
	}{
		{"unknown format", "syslog", 0, "unknown --format"},
		{"year with json", formatJSON, 2026, "--year only applies"},
		{"year with nginx", formatNginx, 2026, "--year only applies"},
		{"year out of range", formatSSHD, 10000, "out of range"},
		{"negative year", formatSSHD, -1, "out of range"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, err := loadEvents("unused", tt.format, tt.year)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// TestFixturesTriggerRules replays each shipped fixture against the shipped
// rules and expects exactly the rule it was written for.
func TestFixturesTriggerRules(t *testing.T) {
	rules, err := rule.LoadDir("../../rules")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name        string
		path        string
		format      string
		year        int
		wantRule    string
		wantMatched int
	}{
		{"json brute force", "../../fixtures/authentication/brute-force.json", formatJSON, 0, "AUTH-001", 17},
		{"sshd brute force", "../../fixtures/authentication/auth.log", formatSSHD, 2026, "AUTH-001", 14},
		{"nginx web scan", "../../fixtures/web/scan.log", formatNginx, 0, "WEB-001", 25},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			events, _, _, err := loadEvents(tt.path, tt.format, tt.year)
			if err != nil {
				t.Fatal(err)
			}
			eng := engine.New(rules)
			for _, ev := range events {
				eng.Evaluate(ev)
			}
			got := eng.Detections()
			if len(got) != 1 || got[0].Rule.ID != tt.wantRule || len(got[0].MatchedEvents) != tt.wantMatched {
				t.Fatalf("want one %s detection matching %d events, got %d detections", tt.wantRule, tt.wantMatched, len(got))
			}
		})
	}
}
