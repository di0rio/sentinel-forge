package engine

import (
	"fmt"
	"testing"
	"time"

	"github.com/di0rio/sentinel-forge/internal/event"
	"github.com/di0rio/sentinel-forge/internal/rule"
)

const bruteForce = `
id: AUTH-001
version: 1
name: Brute Force Authentication
severity: high
when:
  type: authentication_failure
threshold:
  count: 10
  window: 60s
group_by:
  - network.sourceIp
`

var t0 = time.Date(2026, 9, 26, 14, 32, 11, 0, time.UTC)

func mustRule(t *testing.T, src string) rule.Rule {
	t.Helper()
	r, err := rule.Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func failure(n int, ip string, at time.Time) event.Event {
	return event.Event{
		ID:        fmt.Sprintf("evt_%s_%d", ip, n),
		Timestamp: at,
		Source:    "auth-service",
		Type:      "authentication_failure",
		Network:   &event.Network{SourceIP: ip},
	}
}

// failures emits n failures from ip spaced evenly by step.
func failures(n int, ip string, step time.Duration) []event.Event {
	evs := make([]event.Event, n)
	for i := range evs {
		evs[i] = failure(i, ip, t0.Add(time.Duration(i)*step))
	}
	return evs
}

func run(t *testing.T, evs []event.Event) []*Detection {
	t.Helper()
	eng := New([]rule.Rule{mustRule(t, bruteForce)})
	for _, ev := range evs {
		eng.Evaluate(ev)
	}
	return eng.Detections()
}

func TestThreshold(t *testing.T) {
	tests := []struct {
		name        string
		events      []event.Event
		wantCount   int
		wantMatched int
	}{
		{"9 attempts in window", failures(9, "10.0.0.15", 5*time.Second), 0, 0},
		{"10 attempts in window", failures(10, "10.0.0.15", 5*time.Second), 1, 10},
		{"17 attempts in window", failures(17, "10.0.0.15", 2*time.Second), 1, 17},
		{"10 attempts spread beyond window", failures(10, "10.0.0.15", 10*time.Second), 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := run(t, tt.events)
			if len(got) != tt.wantCount {
				t.Fatalf("detections = %d, want %d", len(got), tt.wantCount)
			}
			if tt.wantCount == 1 && len(got[0].MatchedEvents) != tt.wantMatched {
				t.Fatalf("matched = %d, want %d", len(got[0].MatchedEvents), tt.wantMatched)
			}
		})
	}
}

func TestGroupsAreIndependent(t *testing.T) {
	var evs []event.Event
	for i := range 9 {
		at := t0.Add(time.Duration(i) * time.Second)
		evs = append(evs, failure(i, "10.0.0.15", at), failure(i, "10.0.0.16", at))
	}
	if got := run(t, evs); len(got) != 0 {
		t.Fatalf("9 failures per IP must not trigger, got %d detections", len(got))
	}
}

func TestOpenDetectionAbsorbsFollowUpEvents(t *testing.T) {
	// 30 failures 2s apart is one sustained attack, not three alerts.
	got := run(t, failures(30, "10.0.0.15", 2*time.Second))
	if len(got) != 1 {
		t.Fatalf("detections = %d, want 1", len(got))
	}
	if n := len(got[0].MatchedEvents); n != 30 {
		t.Fatalf("matched = %d, want 30", n)
	}
}

func TestNewDetectionAfterQuietPeriod(t *testing.T) {
	first := failures(10, "10.0.0.15", time.Second)
	second := make([]event.Event, 10)
	for i := range second {
		second[i] = failure(100+i, "10.0.0.15", t0.Add(10*time.Minute+time.Duration(i)*time.Second))
	}
	if got := run(t, append(first, second...)); len(got) != 2 {
		t.Fatalf("detections = %d, want 2", len(got))
	}
}

func TestEventsWithoutGroupFieldAreSkipped(t *testing.T) {
	evs := failures(15, "10.0.0.15", time.Second)
	for i := range evs {
		evs[i].Network = nil
	}
	if got := run(t, evs); len(got) != 0 {
		t.Fatalf("detections = %d, want 0", len(got))
	}
}

func TestDisabledRuleIsIgnored(t *testing.T) {
	eng := New([]rule.Rule{mustRule(t, bruteForce+"enabled: false\n")})
	if eng.RuleCount() != 0 {
		t.Fatalf("RuleCount = %d, want 0", eng.RuleCount())
	}
}
