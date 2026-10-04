package parser

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/di0rio/sentinel-forge/internal/event"
)

const (
	nginxSource = "nginx"
	nginxTime   = "02/Jan/2006:15:04:05 -0700"
)

// nginx's "combined" format:
//
//	$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
//
// nginx escapes quotes inside quoted fields (as \x22), so [^"]* is exact.
// Anything after the user agent (extra log_format variables) is ignored.
// $remote_user is logged unescaped apart from quotes, so it may contain "[", "]" and
// spaces; the timestamp is anchored on its fixed shape instead of on brackets.
var nginxCombined = regexp.MustCompile(
	`^(\S+) \S+ .*\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\] "([^"]*)" ([0-9]{3}) ([0-9]+|-) "[^"]*" "([^"]*)"(?: .*)?$`)

// Nginx parses access log lines in nginx's default "combined" format.
// The zero value is ready to use.
type Nginx struct{}

func (Nginx) Parse(line string, lineNo int) (event.Event, bool) {
	m := nginxCombined.FindStringSubmatch(line)
	if m == nil {
		return event.Event{}, false
	}
	ip, ok := normalizeIP(m[1])
	if !ok {
		return event.Event{}, false
	}
	ts, err := time.Parse(nginxTime, m[2])
	if err != nil || ts.IsZero() {
		return event.Event{}, false
	}
	var size int64
	if m[5] != "-" {
		if size, err = strconv.ParseInt(m[5], 10, 64); err != nil {
			return event.Event{}, false
		}
	}

	md := map[string]any{"status": m[4], "bytes": size}
	// The request is "METHOD target PROTOCOL", or arbitrary bytes from a client
	// that did not speak HTTP; keep whatever is recognizable.
	if req := strings.Fields(m[3]); len(req) > 0 {
		setIfPresent(md, "method", req[0])
		if len(req) > 1 {
			setIfPresent(md, "path", req[1])
		}
	}
	setIfPresent(md, "user_agent", m[6])

	return event.Event{
		ID:        fmt.Sprintf("%s-%d", nginxSource, lineNo),
		Timestamp: ts,
		Source:    nginxSource,
		Type:      "http_request",
		Network:   &event.Network{SourceIP: ip},
		Metadata:  md,
	}, true
}

// setIfPresent skips empty values and nginx's "-" placeholder.
func setIfPresent(md map[string]any, key, v string) {
	if v != "" && v != "-" {
		md[key] = v
	}
}
