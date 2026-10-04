package rule

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
		{"metadata key with control characters", "network.sourceIp", `"metadata.x\x1b[2J"`, "metadata keys"},
		{"metadata key with space", "network.sourceIp", `"metadata.a b"`, "metadata keys"},
		{"empty metadata key", "network.sourceIp", "metadata.", "unknown field"},
		{"zero count", "count: 10", "count: 0", "count"},
		{"bad window", "window: 60s", "window: soon", "window"},
		{"window too large", "window: 60s", "window: 48h", "window"},
		{"alias", "type: authentication_failure", "type: &t authentication_failure\nname2: *t", "aliases"},
		{"second document", "version: 1", "version: 1\n---\nid: EVIL-001", "exactly one"},
		{"duplicate key", "version: 1", "version: 1\nversion: 2", "already defined"},
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

// A "billion laughs" document is a few hundred bytes but expands to gigabytes
// when aliases are resolved; it must be rejected without being decoded.
func TestParseRejectsAliasBomb(t *testing.T) {
	var b strings.Builder
	b.WriteString("a: &a [lol, lol, lol, lol, lol, lol, lol, lol, lol]\n")
	prev := "a"
	for _, name := range []string{"b", "c", "d", "e", "f", "g", "h", "i"} {
		b.WriteString(name + ": &" + name + " [" + strings.TrimSuffix(strings.Repeat("*"+prev+", ", 9), ", ") + "]\n")
		prev = name
	}
	src := b.String() + strings.Replace(valid, "group_by:", "tags: *i\ngroup_by:", 1)

	start := time.Now()
	_, err := Parse([]byte(src))
	if err == nil || !strings.Contains(err.Error(), "aliases") {
		t.Fatalf("err = %v, want alias rejection", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("took %s, the document was probably expanded", d)
	}
}

func TestParseRejectsDeepNesting(t *testing.T) {
	src := strings.Repeat("[", 30000) + strings.Repeat("]", 30000)
	if _, err := Parse([]byte(src)); err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadFileRejects(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "big.yml")
	if err := os.WriteFile(big, []byte(valid+"#"+strings.Repeat("x", maxRuleFileSize)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(big); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized file: err = %v", err)
	}
	if _, err := LoadFile(dir); err == nil || !strings.Contains(err.Error(), "regular") {
		t.Fatalf("directory: err = %v", err)
	}
}

func TestLoadDir(t *testing.T) {
	write := func(t *testing.T, dir, name, src string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("duplicate id", func(t *testing.T) {
		dir := t.TempDir()
		write(t, dir, "a.yml", valid)
		write(t, dir, "b.yaml", valid)
		if _, err := LoadDir(dir); err == nil || !strings.Contains(err.Error(), "duplicate rule id") {
			t.Fatalf("err = %v, want duplicate id", err)
		}
	})

	t.Run("symlink is not followed", func(t *testing.T) {
		outside, dir := t.TempDir(), t.TempDir()
		write(t, outside, "secret.yml", valid)
		if err := os.Symlink(filepath.Join(outside, "secret.yml"), filepath.Join(dir, "link.yml")); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		rules, err := LoadDir(dir)
		if err == nil || !strings.Contains(err.Error(), "symbolic link") || len(rules) != 0 {
			t.Fatalf("rules = %d, err = %v, want the link rejected", len(rules), err)
		}
	})
}

func FuzzParse(f *testing.F) {
	f.Add(valid)
	f.Add("a: &a [x]\nb: [*a, *a]\n")
	f.Add("---\n---\n")
	f.Add(strings.Repeat("[", 100))
	f.Fuzz(func(t *testing.T, src string) {
		r, err := Parse([]byte(src))
		if err != nil {
			return
		}
		// Whatever is accepted must be a complete, valid rule.
		if w := r.Threshold.Duration(); w <= 0 || w > maxWindow {
			t.Fatalf("accepted rule with window %s", w)
		}
		if err := r.Validate(); err != nil {
			t.Fatalf("accepted rule fails Validate: %v", err)
		}
	})
}
