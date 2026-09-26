package main

import (
	"os"
	"path/filepath"
	"testing"
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
