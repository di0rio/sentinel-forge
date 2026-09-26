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
	"github.com/di0rio/sentinel-forge/internal/rule"
)

const separator = "────────────────────────────────────────"

func replayCmd() *cobra.Command {
	var rulesDir string
	cmd := &cobra.Command{
		Use:   "replay <file>",
		Short: "Replay a JSON array of events through the detection engine",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			start := time.Now()
			rules, err := rule.LoadDir(rulesDir)
			if err != nil {
				return err
			}
			events, failed, err := readEvents(args[0])
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
			if len(failed) > 0 {
				fmt.Fprintf(out, "✗ %d events rejected\n", len(failed))
				for _, f := range failed {
					fmt.Fprintf(out, "    %s\n", f)
				}
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
	return cmd
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
