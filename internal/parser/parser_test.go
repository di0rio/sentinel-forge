package parser

import (
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/di0rio/sentinel-forge/internal/event"
)

// assertEvent compares events field by field; timestamps are compared by
// instant because parsed zones are distinct pointers.
func assertEvent(t *testing.T, got, want event.Event) {
	t.Helper()
	if !got.Timestamp.Equal(want.Timestamp) {
		t.Errorf("timestamp = %s, want %s", got.Timestamp, want.Timestamp)
	}
	got.Timestamp, want.Timestamp = time.Time{}, time.Time{}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("event mismatch\n got: %+v\nwant: %+v", got, want)
	}
}

// checkInvariants holds for every event a parser returns, whatever the input.
func checkInvariants(t *testing.T, ev event.Event) {
	t.Helper()
	if err := ev.Validate(); err != nil {
		t.Fatalf("parser returned an invalid event: %v", err)
	}
	if ev.Network == nil {
		t.Fatal("event has no network")
	}
	if _, err := netip.ParseAddr(ev.Network.SourceIP); err != nil {
		t.Fatalf("sourceIp %q is not an IP: %v", ev.Network.SourceIP, err)
	}
}

func TestReadAll(t *testing.T) {
	long := strings.Repeat("x", MaxLineBytes+10)
	nginxLine := `203.0.113.7 - - [03/Oct/2026:14:32:11 +0000] "GET / HTTP/1.1" 200 12 "-" "curl/8.5.0"`
	tests := []struct {
		name        string
		input       string
		wantEvents  int
		wantSkipped int
		wantFailed  []string
	}{
		{"empty input", "", 0, 0, nil},
		{"lf and crlf endings", nginxLine + "\n" + nginxLine + "\r\n", 2, 0, nil},
		{"no trailing newline", nginxLine, 1, 0, nil},
		{"noise is skipped", "garbage\n\n" + nginxLine + "\n", 1, 2, nil},
		{
			"over-long line is reported, reading continues",
			nginxLine + "\n" + long + "\n" + nginxLine + "\n", 2, 0,
			[]string{fmt.Sprintf("line 2: exceeds %d bytes", MaxLineBytes)},
		},
		{
			"over-long last line without newline",
			nginxLine + "\n" + long, 1, 0,
			[]string{fmt.Sprintf("line 2: exceeds %d bytes", MaxLineBytes)},
		},
		{"invalid utf-8 does not break parsing", "\xff\xfe" + nginxLine + "\n", 0, 1, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := ReadAll(strings.NewReader(tt.input), Nginx{})
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Events) != tt.wantEvents || res.Skipped != tt.wantSkipped {
				t.Fatalf("events=%d skipped=%d, want events=%d skipped=%d",
					len(res.Events), res.Skipped, tt.wantEvents, tt.wantSkipped)
			}
			if !reflect.DeepEqual(res.Failed, tt.wantFailed) {
				t.Fatalf("failed = %v, want %v", res.Failed, tt.wantFailed)
			}
		})
	}
}

func TestReadAllIsDeterministic(t *testing.T) {
	input := `203.0.113.7 - - [03/Oct/2026:14:32:11 +0000] "GET / HTTP/1.1" 200 12 "-" "curl/8.5.0"` + "\n"
	a, _ := ReadAll(strings.NewReader(input+input), Nginx{})
	b, _ := ReadAll(strings.NewReader(input+input), Nginx{})
	if !reflect.DeepEqual(a, b) {
		t.Fatal("same input produced different events")
	}
	if a.Events[0].ID == a.Events[1].ID {
		t.Fatalf("identical lines must still get distinct IDs, both are %q", a.Events[0].ID)
	}
}

func TestNormalizeIP(t *testing.T) {
	tests := []struct {
		in     string
		want   string
		wantOK bool
	}{
		{"203.0.113.7", "203.0.113.7", true},
		{"2001:db8::1", "2001:db8::1", true},
		{"::ffff:203.0.113.7", "203.0.113.7", true},
		{"fe80::1%eth0", "fe80::1", true},
		{"203.0.113.256", "", false},
		{"example.com", "", false},
		{"-", "", false},
		{"", "", false},
	}
	for _, tt := range tests {
		got, ok := normalizeIP(tt.in)
		if got != tt.want || ok != tt.wantOK {
			t.Errorf("normalizeIP(%q) = %q, %v; want %q, %v", tt.in, got, ok, tt.want, tt.wantOK)
		}
	}
}
