// Package engine evaluates events against rules and produces detections.
//
// Windows use event time (event.Timestamp), never the wall clock, so replaying
// the same events always yields the same detections. Events are expected in
// timestamp order (replay sorts them); out-of-order tolerance is not implemented
// yet, so an event with a far-future timestamp would expire the windows of its
// group. State is bounded by maxStateKeys tracked groups.
package engine

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/di0rio/sentinel-forge/internal/event"
	"github.com/di0rio/sentinel-forge/internal/rule"
)

type Detection struct {
	Rule          *rule.Rule
	Tenant        string
	Group         map[string]string
	MatchedEvents []string
	First         time.Time
	Last          time.Time
}

// Span is the time between the first and last matched event.
func (d *Detection) Span() time.Duration { return d.Last.Sub(d.First) }

// maxStateKeys bounds the per-group state (hit windows plus open detections), so
// an input with endless distinct group_by values cannot exhaust memory.
const maxStateKeys = 100_000

// ErrStateLimit is returned by Evaluate when tracking one more group would
// exceed the state limit and no expired state can be dropped.
var ErrStateLimit = errors.New("too many tracked groups")

type hit struct {
	id string
	ts time.Time
}

type Engine struct {
	rules      []*rule.Rule
	windows    map[string][]hit
	open       map[string]*Detection
	detections []*Detection

	maxKeys   int
	maxWindow time.Duration // longest window of any enabled rule
}

func New(rules []rule.Rule) *Engine {
	e := &Engine{windows: map[string][]hit{}, open: map[string]*Detection{}, maxKeys: maxStateKeys}
	for i := range rules {
		if rules[i].IsEnabled() {
			e.rules = append(e.rules, &rules[i])
			e.maxWindow = max(e.maxWindow, rules[i].Threshold.Duration())
		}
	}
	return e
}

func (e *Engine) RuleCount() int { return len(e.rules) }

// Evaluate feeds one event through every rule. While a detection is open
// (matching events keep arriving within the rule window), further matches
// extend it instead of opening a new one, which prevents one attack from
// producing an alert per event.
//
// It fails with ErrStateLimit when the number of tracked groups reaches the
// limit; the event is then not evaluated and the engine should be discarded.
func (e *Engine) Evaluate(ev event.Event) error {
	for _, r := range e.rules {
		if !r.Matches(ev) {
			continue
		}
		group, ok := groupOf(r, ev)
		if !ok {
			continue
		}
		key := stateKey(r, ev.Tenant, group)
		window := r.Threshold.Duration()

		if d := e.open[key]; d != nil {
			if ev.Timestamp.Sub(d.Last) <= window {
				d.MatchedEvents = append(d.MatchedEvents, ev.ID)
				d.Last = ev.Timestamp
				continue
			}
			delete(e.open, key)
		}

		if err := e.reserve(key, ev.Timestamp); err != nil {
			return fmt.Errorf("rule %s: %w (limit %d)", r.ID, err, e.maxKeys)
		}

		hits := append(prune(e.windows[key], ev.Timestamp.Add(-window)), hit{ev.ID, ev.Timestamp})
		if len(hits) < r.Threshold.Count {
			e.windows[key] = hits
			continue
		}
		delete(e.windows, key)

		d := &Detection{Rule: r, Tenant: ev.Tenant, Group: group, First: hits[0].ts, Last: ev.Timestamp}
		for _, h := range hits {
			d.MatchedEvents = append(d.MatchedEvents, h.id)
		}
		e.open[key] = d
		e.detections = append(e.detections, d)
	}
	return nil
}

// Detections returns every detection opened so far, in creation order.
func (e *Engine) Detections() []*Detection { return e.detections }

// groupOf extracts the group_by values; events missing any of them are skipped.
func groupOf(r *rule.Rule, ev event.Event) (map[string]string, bool) {
	group := make(map[string]string, len(r.GroupBy))
	for _, path := range r.GroupBy {
		v, ok := ev.Field(path)
		if !ok {
			return nil, false
		}
		group[path] = v
	}
	return group, true
}

func stateKey(r *rule.Rule, tenant string, group map[string]string) string {
	// Length-prefixed, so values containing any byte cannot collide with
	// another tenant/group split.
	var b strings.Builder
	write := func(s string) {
		b.WriteString(strconv.Itoa(len(s)))
		b.WriteByte(':')
		b.WriteString(s)
	}
	write(r.ID)
	write(tenant)
	for _, path := range r.GroupBy {
		write(group[path])
	}
	return b.String()
}

// prune drops hits older than cutoff; hits are in timestamp order.
func prune(hits []hit, cutoff time.Time) []hit {
	i := 0
	for i < len(hits) && hits[i].ts.Before(cutoff) {
		i++
	}
	return hits[i:]
}

// reserve makes room to track key. At the limit it first drops state older
// than every rule window, which can no longer contribute to a detection.
func (e *Engine) reserve(key string, now time.Time) error {
	if _, ok := e.windows[key]; ok || len(e.windows)+len(e.open) < e.maxKeys {
		return nil
	}
	cutoff := now.Add(-e.maxWindow)
	for k, hits := range e.windows {
		if hits[len(hits)-1].ts.Before(cutoff) {
			delete(e.windows, k)
		}
	}
	for k, d := range e.open {
		if d.Last.Before(cutoff) {
			delete(e.open, k)
		}
	}
	if len(e.windows)+len(e.open) >= e.maxKeys {
		return ErrStateLimit
	}
	return nil
}
