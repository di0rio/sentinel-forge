// Package event defines the normalized SecurityEvent consumed by the detection engine.
package event

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

type Actor struct {
	Username string `json:"username,omitempty"`
}

type Network struct {
	SourceIP string `json:"sourceIp,omitempty"`
}

type Target struct {
	Host string `json:"host,omitempty"`
}

type Event struct {
	ID        string         `json:"id"`
	Tenant    string         `json:"tenant,omitempty"`
	Timestamp time.Time      `json:"timestamp"`
	Source    string         `json:"source"`
	Type      string         `json:"type"`
	Actor     *Actor         `json:"actor,omitempty"`
	Network   *Network       `json:"network,omitempty"`
	Target    *Target        `json:"target,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// Validate rejects events missing the fields every detection depends on.
func (e Event) Validate() error {
	var errs []error
	if e.ID == "" {
		errs = append(errs, errors.New("id is required"))
	}
	if e.Timestamp.IsZero() {
		errs = append(errs, errors.New("timestamp is required"))
	}
	if e.Source == "" {
		errs = append(errs, errors.New("source is required"))
	}
	if e.Type == "" {
		errs = append(errs, errors.New("type is required"))
	}
	return errors.Join(errs...)
}

// fields maps the paths rules may reference to their accessors.
// Rules can only read these paths; nothing is resolved dynamically.
var fields = map[string]func(Event) string{
	"type":   func(e Event) string { return e.Type },
	"source": func(e Event) string { return e.Source },
	"actor.username": func(e Event) string {
		if e.Actor == nil {
			return ""
		}
		return e.Actor.Username
	},
	"network.sourceIp": func(e Event) string {
		if e.Network == nil {
			return ""
		}
		return e.Network.SourceIP
	},
	"target.host": func(e Event) string {
		if e.Target == nil {
			return ""
		}
		return e.Target.Host
	},
}

const metadataPrefix = "metadata."

// IsField reports whether path can be referenced by a rule.
func IsField(path string) bool {
	if _, ok := fields[path]; ok {
		return true
	}
	return strings.HasPrefix(path, metadataPrefix) && len(path) > len(metadataPrefix)
}

// Field returns the string value at path, or false when absent or empty.
func (e Event) Field(path string) (string, bool) {
	if get, ok := fields[path]; ok {
		v := get(e)
		return v, v != ""
	}
	if key, ok := strings.CutPrefix(path, metadataPrefix); ok {
		v, ok := e.Metadata[key]
		if !ok || v == nil {
			return "", false
		}
		return fmt.Sprint(v), true
	}
	return "", false
}
