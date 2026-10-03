package parser

import (
	"testing"
	"time"

	"github.com/di0rio/sentinel-forge/internal/event"
)

func nginxEvent(id, ip string, md map[string]any) event.Event {
	return event.Event{
		ID:        id,
		Timestamp: time.Date(2026, 10, 3, 14, 32, 11, 0, time.UTC),
		Source:    "nginx",
		Type:      "http_request",
		Network:   &event.Network{SourceIP: ip},
		Metadata:  md,
	}
}

func TestNginxParse(t *testing.T) {
	tests := []struct {
		name string
		line string
		want *event.Event // nil: the line must be skipped
	}{
		{
			"ordinary request",
			`203.0.113.7 - - [03/Oct/2026:14:32:11 +0000] "GET /index.html HTTP/1.1" 200 612 "https://example.com/" "Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0"`,
			ptr(nginxEvent("nginx-1", "203.0.113.7", map[string]any{
				"status": "200", "bytes": int64(612), "method": "GET", "path": "/index.html",
				"user_agent": "Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0",
			})),
		},
		{
			"scanner 404 with query string and authenticated user",
			`198.51.100.77 - bob [03/Oct/2026:16:32:11 +0200] "GET /wp-login.php?redirect_to=%2F HTTP/1.1" 404 153 "-" "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)"`,
			ptr(nginxEvent("nginx-1", "198.51.100.77", map[string]any{
				"status": "404", "bytes": int64(153), "method": "GET", "path": "/wp-login.php?redirect_to=%2F",
				"user_agent": "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
			})),
		},
		{
			"dash bytes, referer and user agent",
			`203.0.113.7 - - [03/Oct/2026:14:32:11 +0000] "POST /api HTTP/2.0" 304 - "-" "-"`,
			ptr(nginxEvent("nginx-1", "203.0.113.7", map[string]any{
				"status": "304", "bytes": int64(0), "method": "POST", "path": "/api",
			})),
		},
		{
			"ipv6 client",
			`2001:db8::1 - - [03/Oct/2026:14:32:11 +0000] "HEAD / HTTP/1.1" 200 0 "-" "curl/8.5.0"`,
			ptr(nginxEvent("nginx-1", "2001:db8::1", map[string]any{
				"status": "200", "bytes": int64(0), "method": "HEAD", "path": "/", "user_agent": "curl/8.5.0",
			})),
		},
		{
			"extra trailing log_format field",
			`203.0.113.7 - - [03/Oct/2026:14:32:11 +0000] "GET / HTTP/1.1" 200 5 "-" "curl/8.5.0" "198.51.100.1"`,
			ptr(nginxEvent("nginx-1", "203.0.113.7", map[string]any{
				"status": "200", "bytes": int64(5), "method": "GET", "path": "/", "user_agent": "curl/8.5.0",
			})),
		},
		{
			"client that did not speak http",
			`203.0.113.7 - - [03/Oct/2026:14:32:11 +0000] "\x16\x03\x01\x02" 400 150 "-" "-"`,
			ptr(nginxEvent("nginx-1", "203.0.113.7", map[string]any{
				"status": "400", "bytes": int64(150), "method": `\x16\x03\x01\x02`,
			})),
		},
		{
			"empty request logged as dash",
			`203.0.113.7 - - [03/Oct/2026:14:32:11 +0000] "-" 408 0 "-" "-"`,
			ptr(nginxEvent("nginx-1", "203.0.113.7", map[string]any{"status": "408", "bytes": int64(0)})),
		},
		{"invalid ip", `203.0.113.999 - - [03/Oct/2026:14:32:11 +0000] "GET / HTTP/1.1" 200 5 "-" "-"`, nil},
		{"hostname as client", `example.com - - [03/Oct/2026:14:32:11 +0000] "GET / HTTP/1.1" 200 5 "-" "-"`, nil},
		{"bad timestamp", `203.0.113.7 - - [32/Oct/2026:14:32:11 +0000] "GET / HTTP/1.1" 200 5 "-" "-"`, nil},
		{"zero timestamp", `203.0.113.7 - - [01/Jan/0001:00:00:00 +0000] "GET / HTTP/1.1" 200 5 "-" "-"`, nil},
		{"status is not three digits", `203.0.113.7 - - [03/Oct/2026:14:32:11 +0000] "GET / HTTP/1.1" 2000 5 "-" "-"`, nil},
		{"bytes overflow", `203.0.113.7 - - [03/Oct/2026:14:32:11 +0000] "GET / HTTP/1.1" 200 99999999999999999999 "-" "-"`, nil},
		{"unterminated user agent", `203.0.113.7 - - [03/Oct/2026:14:32:11 +0000] "GET / HTTP/1.1" 200 5 "-" "curl`, nil},
		{"common log format (no referer or agent)", `203.0.113.7 - - [03/Oct/2026:14:32:11 +0000] "GET / HTTP/1.1" 200 5`, nil},
		{"nginx error log line", `2026/10/03 14:32:11 [error] 1#1: *1 open() "/usr/share/nginx/html/x" failed (2: No such file or directory), client: 203.0.113.7`, nil},
		{"truncated line", `203.0.113.7 - - [03/Oct/2026:14:32:1`, nil},
		{"empty", "", nil},
		{"binary junk", "\x00\x01\x02\xff\xfe", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Nginx{}.Parse(tt.line, 1)
			if tt.want == nil {
				if ok {
					t.Fatalf("line must be skipped, got %+v", got)
				}
				return
			}
			if !ok {
				t.Fatal("line must parse")
			}
			assertEvent(t, got, *tt.want)
		})
	}
}

func TestNginxTimestampOffset(t *testing.T) {
	got, ok := Nginx{}.Parse(`203.0.113.7 - - [03/Oct/2026:16:32:11 +0200] "GET / HTTP/1.1" 200 5 "-" "-"`, 1)
	if !ok {
		t.Fatal("line must parse")
	}
	if want := time.Date(2026, 10, 3, 14, 32, 11, 0, time.UTC); !got.Timestamp.Equal(want) {
		t.Fatalf("timestamp = %s, want %s", got.Timestamp, want)
	}
}

func FuzzParseNginx(f *testing.F) {
	for _, seed := range []string{
		`203.0.113.7 - - [03/Oct/2026:14:32:11 +0000] "GET /index.html HTTP/1.1" 200 612 "https://example.com/" "Mozilla/5.0"`,
		`2001:db8::1 - bob [03/Oct/2026:16:32:11 +0200] "POST /api HTTP/2.0" 304 - "-" "-" "extra"`,
		`203.0.113.7 - - [03/Oct/2026:14:32:11 +0000] "\x16\x03\x01" 400 150 "-" "-"`,
		`203.0.113.7 - - [01/Jan/0001:00:00:00 +0000] "-" 408 0 "-" "-"`,
		"",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, line string) {
		if ev, ok := (Nginx{}).Parse(line, 1); ok {
			checkInvariants(t, ev)
		}
	})
}
