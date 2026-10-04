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

func TestGroupValuesWithSeparatorsDoNotCollide(t *testing.T) {
	r := mustRule(t, `
id: AUTH-002
version: 1
name: Two field group
severity: low
when:
  type: authentication_failure
threshold:
  count: 2
  window: 60s
group_by:
  - actor.username
  - target.host
`)
	a := failure(1, "10.0.0.1", t0)
	a.Actor, a.Target = &event.Actor{Username: "a\x00b"}, &event.Target{Host: "c"}
	b := failure(2, "10.0.0.1", t0.Add(time.Second))
	b.Actor, b.Target = &event.Actor{Username: "a"}, &event.Target{Host: "b\x00c"}

	eng := New([]rule.Rule{r})
	for _, ev := range []event.Event{a, b} {
		eng.Evaluate(ev)
	}
	if got := eng.Detections(); len(got) != 0 {
		t.Fatalf("distinct groups were merged: %d detections", len(got))
	}
}

func TestStateLimit(t *testing.T) {
	newEngine := func() *Engine {
		eng := New([]rule.Rule{mustRule(t, bruteForce)})
		eng.maxKeys = 3
		return eng
	}
	ips := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"}

	t.Run("live groups over the limit are evicted and counted", func(t *testing.T) {
		eng := newEngine()
		for i, ip := range ips {
			eng.Evaluate(failure(i, ip, t0.Add(time.Duration(i)*time.Second)))
		}
		if eng.Evicted() != 1 || len(eng.windows) != 3 {
			t.Fatalf("evicted = %d, tracked = %d, want 1 and 3", eng.Evicted(), len(eng.windows))
		}
		if _, ok := eng.windows[stateKey(eng.rules[0], "", map[string]string{"network.sourceIp": "10.0.0.1"})]; ok {
			t.Fatal("the least recently active group must be the one evicted")
		}
	})

	t.Run("expired groups are dropped", func(t *testing.T) {
		eng := newEngine()
		for i, ip := range ips {
			// Each group is a day after the previous one, far outside the window.
			eng.Evaluate(failure(i, ip, t0.Add(time.Duration(i)*48*time.Hour)))
		}
		if n := len(eng.windows); n > 3 {
			t.Fatalf("tracked groups = %d, want <= 3", n)
		}
		if eng.Evicted() != 0 {
			t.Fatalf("evicted = %d, want 0: expired state is dropped, not evicted", eng.Evicted())
		}
	})

	t.Run("known groups keep working at the limit", func(t *testing.T) {
		eng := newEngine()
		for i, ip := range ips[:3] {
			eng.Evaluate(failure(i, ip, t0))
		}
		eng.Evaluate(failure(9, ips[0], t0.Add(time.Second)))
		if eng.Evicted() != 0 {
			t.Fatalf("evicted = %d, want 0", eng.Evicted())
		}
	})
}

// A flood of distinct sources must never erase a detection already raised, and
// must not stop later attacks from being detected.
func TestStateFloodKeepsDetections(t *testing.T) {
	eng := New([]rule.Rule{mustRule(t, bruteForce)})
	for _, ev := range failures(12, "203.0.113.45", time.Second) {
		eng.Evaluate(ev)
	}
	// More distinct addresses than the state limit, all inside one window.
	at := t0.Add(20 * time.Second)
	for i := range maxStateKeys + 10 {
		ip := fmt.Sprintf("2001:db8::%x:%x", i>>16, i&0xffff)
		eng.Evaluate(failure(i, ip, at))
	}
	if eng.Evicted() == 0 {
		t.Fatal("flood must hit the state limit")
	}
	if n := len(eng.windows) + len(eng.open); n > maxStateKeys {
		t.Fatalf("tracked groups = %d, want <= %d", n, maxStateKeys)
	}
	if got := eng.Detections(); len(got) != 1 || got[0].Group["network.sourceIp"] != "203.0.113.45" {
		t.Fatalf("detections after flood = %d, want the original brute force", len(got))
	}

	// An attack that starts after the flood is still detected.
	for i := range 10 {
		eng.Evaluate(failure(1000+i, "198.51.100.9", at.Add(time.Duration(i)*time.Second)))
	}
	if got := eng.Detections(); len(got) != 2 {
		t.Fatalf("detections = %d, want the post-flood brute force too", len(got))
	}
}
