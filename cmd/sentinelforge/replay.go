package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/di0rio/sentinel-forge/internal/engine"
	"github.com/di0rio/sentinel-forge/internal/event"
	"github.com/di0rio/sentinel-forge/internal/parser"
	"github.com/di0rio/sentinel-forge/internal/rule"
)

const separator = "────────────────────────────────────────"

const (
	formatJSON  = "json"
	formatSSHD  = "sshd"
	formatNginx = "nginx"
)

func replayCmd() *cobra.Command {
	var (
		rulesDir string
		format   string
		year     int
	)
	cmd := &cobra.Command{
		Use:   "replay <file>",
		Short: "Replay events (a JSON array or a raw log) through the detection engine",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			start := time.Now()
			rules, err := rule.LoadDir(rulesDir)
			if err != nil {
				return err
			}
			events, failed, skipped, err := loadEvents(args[0], format, year)
			if err != nil {
				return err
			}

			eng := engine.New(rules)
			for _, ev := range events {
				eng.Evaluate(ev)
			}

			out := cmd.OutOrStdout()
			fmt.Fprintln(out, "SentinelForge Detection Engine")
			fmt.Fprintln(out)
			fmt.Fprintf(out, "✓ %d events processed\n", len(events))
			unit := "events"
			if format != formatJSON {
				unit = "lines"
			}
			if len(failed) > 0 {
				fmt.Fprintf(out, "✗ %d %s rejected\n", len(failed), unit)
				for _, f := range failed {
					fmt.Fprintf(out, "    %s\n", f)
				}
			}
			if skipped > 0 {
				fmt.Fprintf(out, "· %d lines skipped (not security events)\n", skipped)
			}
			fmt.Fprintf(out, "✓ %d rules evaluated\n", eng.RuleCount())
			fmt.Fprintln(out)
			for _, d := range eng.Detections() {
				printDetection(out, d)
			}
			fmt.Fprintln(out, separator)
			fmt.Fprintln(out)
			fmt.Fprintf(out, "%d detections in %s\n", len(eng.Detections()), time.Since(start).Round(time.Millisecond))
			return nil
		},
	}
	cmd.Flags().StringVar(&rulesDir, "rules", "rules", "directory containing rule files")
	cmd.Flags().StringVar(&format, "format", formatJSON, "input format: json, sshd or nginx")
	cmd.Flags().IntVar(&year, "year", 0, "year of classic syslog timestamps, which carry none (sshd only; default: current year)")
	return cmd
}

// loadEvents reads path in the given format. skipped counts log lines that are
// not security events; it is always 0 for JSON, where every element is validated.
func loadEvents(path, format string, year int) (events []event.Event, failed []string, skipped int, err error) {
	if year != 0 && format != formatSSHD {
		return nil, nil, 0, fmt.Errorf("--year only applies to --format %s", formatSSHD)
	}
	switch format {
	case formatJSON:
		events, failed, err = readEvents(path)
		return events, failed, 0, err
	case formatSSHD:
		if year < 0 || year > 9999 {
			return nil, nil, 0, fmt.Errorf("--year %d is out of range", year)
		}
		return readLog(path, parser.NewSSHD(parser.WithYear(year)))
	case formatNginx:
		return readLog(path, parser.Nginx{})
	default:
		return nil, nil, 0, fmt.Errorf("unknown --format %q: want %s, %s or %s", format, formatJSON, formatSSHD, formatNginx)
	}
}

// readLog parses a raw log line by line. Lines that are over-long are
// reported in failed, other unusable lines are counted in skipped.
// Events are returned sorted by timestamp.
func readLog(path string, p parser.Parser) ([]event.Event, []string, int, error) {
	f, err := os.Open(path) //nolint:gosec // path is chosen by the CLI user
	if err != nil {
		return nil, nil, 0, err
	}
	defer func() { _ = f.Close() }() // read-only: a failed close loses nothing
	res, err := parser.ReadAll(f, p)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("%s: %w", path, err)
	}
	slices.SortStableFunc(res.Events, func(a, b event.Event) int { return a.Timestamp.Compare(b.Timestamp) })
	return res.Events, res.Failed, res.Skipped, nil
}

// readEvents decodes a JSON array, validating each event on its own so one
// malformed event is reported instead of aborting the whole replay.
// Valid events are returned sorted by timestamp.
func readEvents(path string) ([]event.Event, []string, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is chosen by the CLI user
	if err != nil {
		return nil, nil, err
	}
	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, nil, fmt.Errorf("%s: expected a JSON array of events: %w", path, err)
	}

	var (
		events []event.Event
		failed []string
	)
	for i, msg := range raw {
		var ev event.Event
		dec := json.NewDecoder(bytes.NewReader(msg))
		dec.DisallowUnknownFields()
		err := dec.Decode(&ev)
		if err == nil {
			err = ev.Validate()
		}
		if err != nil {
			failed = append(failed, fmt.Sprintf("event[%d]: %s", i, strings.ReplaceAll(err.Error(), "\n", "; ")))
			continue
		}
		events = append(events, ev)
	}
	slices.SortStableFunc(events, func(a, b event.Event) int { return a.Timestamp.Compare(b.Timestamp) })
	return events, failed, nil
}

func printDetection(out io.Writer, d *engine.Detection) {
	r := d.Rule
	group := make([]string, 0, len(r.GroupBy))
	for _, path := range r.GroupBy {
		group = append(group, path+"="+d.Group[path])
	}
	where := strings.Join(group, ", ")

	fmt.Fprintln(out, separator)
	fmt.Fprintln(out)
	fmt.Fprintln(out, "🚨 Detection triggered")
	fmt.Fprintln(out)
	fmt.Fprintf(out, "%s v%d\n%s\n\n", r.ID, r.Version, r.Name)
	fmt.Fprintf(out, "Severity:      %s\n", strings.ToUpper(r.Severity))
	if where != "" {
		fmt.Fprintf(out, "Group:         %s\n", where)
	}
	fmt.Fprintf(out, "Matched:       %d events\n", len(d.MatchedEvents))
	fmt.Fprintf(out, "Window:        %s (%s → %s)\n", d.Span(), d.First.Format(time.TimeOnly), d.Last.Format(time.TimeOnly))
	fmt.Fprintf(out, "Threshold:     %d events / %s\n", r.Threshold.Count, r.Threshold.Window)
	if r.Attack != nil {
		fmt.Fprintf(out, "MITRE ATT&CK:  %s (%s)\n", r.Attack.Technique, r.Attack.Tactic)
	}
	fmt.Fprintln(out)
	fmt.Fprintf(out, "Reason:\n%d events matched %s, reaching the threshold of %d within %s.\n\n",
		len(d.MatchedEvents), conditions(r), r.Threshold.Count, r.Threshold.Window)
}

func conditions(r *rule.Rule) string {
	parts := make([]string, 0, len(r.When))
	for path, v := range r.When {
		parts = append(parts, path+"="+v)
	}
	slices.Sort(parts)
	return strings.Join(parts, ", ")
}
