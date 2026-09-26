// Package engine evaluates events against rules and produces detections.
//
// Windows use event time (event.Timestamp), never the wall clock, so replaying
// the same events always yields the same detections. Events are expected in
// timestamp order; out-of-order tolerance is not implemented yet.
package engine

import (
	"strings"
	"time"

	"github.com/di0rio/sentinelforge/internal/event"
	"github.com/di0rio/sentinelforge/internal/rule"
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

type hit struct {
	id string
	ts time.Time
}

type Engine struct {
	rules      []*rule.Rule
	windows    map[string][]hit
	open       map[string]*Detection
	detections []*Detection
}

func New(rules []rule.Rule) *Engine {
	e := &Engine{windows: map[string][]hit{}, open: map[string]*Detection{}}
	for i := range rules {
		if rules[i].IsEnabled() {
			e.rules = append(e.rules, &rules[i])
		}
	}
	return e
}

func (e *Engine) RuleCount() int { return len(e.rules) }

// Evaluate feeds one event through every rule. While a detection is open
// (matching events keep arriving within the rule window), further matches
// extend it instead of opening a new one, which prevents one attack from
// producing an alert per event.
func (e *Engine) Evaluate(ev event.Event) {
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
	var b strings.Builder
	b.WriteString(r.ID)
	b.WriteByte(0)
	b.WriteString(tenant)
	for _, path := range r.GroupBy {
		b.WriteByte(0)
		b.WriteString(group[path])
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
