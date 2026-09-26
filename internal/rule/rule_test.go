package rule

import (
	"strings"
	"testing"
)

const valid = `
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

func TestParseValid(t *testing.T) {
	r, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if r.Threshold.Duration().Seconds() != 60 {
		t.Fatalf("window = %s, want 60s", r.Threshold.Duration())
	}
	if !r.IsEnabled() {
		t.Fatal("rule should default to enabled")
	}
}

func TestParseRejects(t *testing.T) {
	tests := []struct {
		name    string
		old     string
		new     string
		wantErr string
	}{
		{"unknown field", "version: 1", "version: 1\nexec: rm -rf /", "exec"},
		{"bad id", "AUTH-001", "auth_1", "id"},
		{"bad severity", "severity: high", "severity: extreme", "severity"},
		{"unknown when field", "type: authentication_failure", "process.cmdline: x", "unknown field"},
		{"unknown group_by field", "network.sourceIp", "network.ttl", "unknown field"},
		{"zero count", "count: 10", "count: 0", "count"},
		{"bad window", "window: 60s", "window: soon", "window"},
		{"window too large", "window: 60s", "window: 48h", "window"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := strings.Replace(valid, tt.old, tt.new, 1)
			_, err := Parse([]byte(src))
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %q does not mention %q", err, tt.wantErr)
			}
		})
	}
}

func TestRepositoryRulesAreValid(t *testing.T) {
	rules, err := LoadDir("../../rules")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) == 0 {
		t.Fatal("no rules found")
	}
}
