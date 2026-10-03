// Package rule loads and validates declarative detection rules.
//
// Rules are data only: a restricted YAML schema with no expressions,
// templates or code execution. Unknown fields are rejected.
package rule

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"

	"github.com/di0rio/sentinel-forge/internal/event"
)

const (
	maxRuleFileSize = 64 << 10
	maxWindow       = 24 * time.Hour
)

var idPattern = regexp.MustCompile(`^[A-Z]+-[0-9]{3}$`)

var severities = map[string]bool{"low": true, "medium": true, "high": true, "critical": true}

type Threshold struct {
	Count  int    `yaml:"count"`
	Window string `yaml:"window"`

	window time.Duration
}

// Duration is the parsed window; valid only after Validate.
func (t Threshold) Duration() time.Duration { return t.window }

type Attack struct {
	Tactic    string `yaml:"tactic"`
	Technique string `yaml:"technique"`
}

type Rule struct {
	ID          string            `yaml:"id"`
	Version     int               `yaml:"version"`
	Name        string            `yaml:"name"`
	Description string            `yaml:"description"`
	Severity    string            `yaml:"severity"`
	Enabled     *bool             `yaml:"enabled"`
	Tags        []string          `yaml:"tags"`
	When        map[string]string `yaml:"when"`
	Threshold   Threshold         `yaml:"threshold"`
	GroupBy     []string          `yaml:"group_by"`
	Attack      *Attack           `yaml:"attack"`
	References  []string          `yaml:"references"`
}

// IsEnabled defaults to true when the field is omitted.
func (r Rule) IsEnabled() bool { return r.Enabled == nil || *r.Enabled }

// Matches reports whether every `when` condition equals the event's field.
func (r Rule) Matches(e event.Event) bool {
	for path, want := range r.When {
		if got, ok := e.Field(path); !ok || got != want {
			return false
		}
	}
	return true
}

func (r *Rule) Validate() error {
	var errs []error
	if !idPattern.MatchString(r.ID) {
		errs = append(errs, fmt.Errorf("id %q must match %s", r.ID, idPattern))
	}
	if r.Version < 1 {
		errs = append(errs, errors.New("version must be >= 1"))
	}
	if strings.TrimSpace(r.Name) == "" {
		errs = append(errs, errors.New("name is required"))
	}
	if !severities[r.Severity] {
		errs = append(errs, fmt.Errorf("severity %q must be one of low, medium, high, critical", r.Severity))
	}
	if len(r.When) == 0 {
		errs = append(errs, errors.New("when must have at least one condition"))
	}
	for path := range r.When {
		if !event.IsField(path) {
			errs = append(errs, fmt.Errorf("when: unknown field %q", path))
		}
	}
	for _, path := range r.GroupBy {
		if !event.IsField(path) {
			errs = append(errs, fmt.Errorf("group_by: unknown field %q", path))
		}
	}
	if r.Threshold.Count < 1 {
		errs = append(errs, errors.New("threshold.count must be >= 1"))
	}
	w, err := time.ParseDuration(r.Threshold.Window)
	switch {
	case err != nil:
		errs = append(errs, fmt.Errorf("threshold.window: %w", err))
	case w <= 0 || w > maxWindow:
		errs = append(errs, fmt.Errorf("threshold.window must be in (0, %s]", maxWindow))
	default:
		r.Threshold.window = w
	}
	return errors.Join(errs...)
}

// Parse decodes and validates a single rule document.
//
// YAML aliases are rejected: decoding expands them, so a few hundred bytes of
// nested aliases ("billion laughs") would exhaust memory and CPU. Rules have
// no use for them.
func Parse(data []byte) (r Rule, err error) {
	// goccy/go-yaml v1.19.2 can panic on malformed tags (found by FuzzParse); a
	// bad rule file must be an error, not a crash.
	defer func() {
		if p := recover(); p != nil {
			r, err = Rule{}, fmt.Errorf("invalid YAML (decoder panic: %v)", p)
		}
	}()
	if err := checkYAML(data); err != nil {
		return Rule{}, err
	}
	if err := yaml.UnmarshalWithOptions(data, &r, yaml.Strict()); err != nil {
		return Rule{}, err
	}
	if err := r.Validate(); err != nil {
		return Rule{}, err
	}
	return r, nil
}

func LoadFile(path string) (Rule, error) {
	f, err := os.Open(path) //nolint:gosec // rule paths come from the operator, not from event data
	if err != nil {
		return Rule{}, err
	}
	defer func() { _ = f.Close() }() // read-only: a failed close loses nothing
	// Check the opened file, not the path, so it cannot be swapped after the check;
	// devices and FIFOs report size 0 but never end.
	info, err := f.Stat()
	if err != nil {
		return Rule{}, err
	}
	if !info.Mode().IsRegular() {
		return Rule{}, fmt.Errorf("%s: not a regular file", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxRuleFileSize+1))
	if err != nil {
		return Rule{}, err
	}
	if len(data) > maxRuleFileSize {
		return Rule{}, fmt.Errorf("%s: file exceeds %d bytes", path, maxRuleFileSize)
	}
	r, err := Parse(data)
	if err != nil {
		return Rule{}, fmt.Errorf("%s: %w", path, err)
	}
	return r, nil
}

// LoadDir loads every *.yml / *.yaml under dir, sorted by ID.
// All files are checked; errors are returned together.
func LoadDir(dir string) ([]Rule, error) {
	var (
		rules []Rule
		errs  []error
		seen  = map[string]string{}
	)
	walkErr := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		ext := filepath.Ext(path)
		if d.IsDir() || (ext != ".yml" && ext != ".yaml") {
			return nil
		}
		// A link could point outside the rules directory.
		if d.Type()&fs.ModeSymlink != 0 {
			errs = append(errs, fmt.Errorf("%s: symbolic links are not allowed", path))
			return nil
		}
		r, err := LoadFile(path)
		if err != nil {
			errs = append(errs, err)
			return nil
		}
		if prev, dup := seen[r.ID]; dup {
			errs = append(errs, fmt.Errorf("%s: duplicate rule id %s (also in %s)", path, r.ID, prev))
			return nil
		}
		seen[r.ID] = path
		rules = append(rules, r)
		return nil
	})
	if walkErr != nil {
		errs = append(errs, walkErr)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	return rules, errors.Join(errs...)
}

// checkYAML requires exactly one document without aliases.
func checkYAML(data []byte) error {
	file, err := parser.ParseBytes(data, 0)
	if err != nil {
		return err
	}
	if len(file.Docs) != 1 {
		return fmt.Errorf("expected exactly one YAML document, found %d", len(file.Docs))
	}
	var f aliasFinder
	ast.Walk(&f, file.Docs[0])
	if f.found {
		return errors.New("YAML aliases are not allowed")
	}
	return nil
}

type aliasFinder struct{ found bool }

func (f *aliasFinder) Visit(n ast.Node) ast.Visitor {
	if _, ok := n.(*ast.AliasNode); ok {
		f.found = true
	}
	return f
}
