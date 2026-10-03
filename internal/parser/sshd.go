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
	sshdSource    = "sshd"
	classicLayout = "Jan _2 15:04:05" // "Oct  3 14:32:11": 15 bytes, no year
	classicLen    = len(classicLayout)
)

var (
	// After the timestamp: "<host> sshd[<pid>]: <message>". OpenSSH 9.8+ logs
	// authentication from the sshd-session binary.
	sshdHeader = regexp.MustCompile(`^(\S+) sshd(?:-session)?(?:\[[0-9]+\])?: (.*)$`)

	// Usernames are attacker-controlled and may contain spaces, so they are
	// matched greedily: the last " from <ip> port <n>" is the one sshd appended.
	sshdFailed   = regexp.MustCompile(`^Failed (\S+) for (invalid user )?(.+) from (\S+) port ([0-9]{1,5})(?: ssh2)?$`)
	sshdInvalid  = regexp.MustCompile(`^Invalid user (.+) from (\S+)(?: port ([0-9]{1,5}))?$`)
	sshdAccepted = regexp.MustCompile(`^Accepted (\S+) for (\S+) from (\S+) port ([0-9]{1,5})(?: ssh2)?(?::.*)?$`)
)

// SSHD parses OpenSSH server lines from auth.log, /var/log/secure or journald
// exports, in either the classic syslog or the ISO 8601 timestamp format.
//
// Classic timestamps carry no year, so one is supplied (see WithYear). A log
// that spans New Year read with a single year will have its January lines
// dated before its December ones.
type SSHD struct {
	year int
	loc  *time.Location
}

// SSHDOption configures an SSHD parser.
type SSHDOption func(*SSHD)

// WithYear sets the year given to classic syslog timestamps. Zero (the
// default) means the current year; pass a year for reproducible results.
func WithYear(year int) SSHDOption { return func(s *SSHD) { s.year = year } }

// WithLocation sets the zone of classic syslog timestamps (default UTC).
// ISO 8601 timestamps carry their own offset and ignore it.
func WithLocation(loc *time.Location) SSHDOption {
	return func(s *SSHD) {
		if loc != nil {
			s.loc = loc
		}
	}
}

func NewSSHD(opts ...SSHDOption) *SSHD {
	s := &SSHD{loc: time.UTC}
	for _, opt := range opts {
		opt(s)
	}
	if s.year == 0 {
		s.year = time.Now().In(s.loc).Year()
	}
	return s
}

func (s *SSHD) Parse(line string, lineNo int) (event.Event, bool) {
	ts, rest, ok := s.splitTimestamp(line)
	if !ok || ts.IsZero() {
		return event.Event{}, false
	}
	hdr := sshdHeader.FindStringSubmatch(rest)
	if hdr == nil {
		return event.Event{}, false
	}
	host, msg := hdr[1], hdr[2]

	var (
		typ, user, ip string
		md            = map[string]any{}
	)
	switch {
	case sshdFailed.MatchString(msg):
		m := sshdFailed.FindStringSubmatch(msg)
		typ, user, ip = "authentication_failure", m[3], m[4]
		md["method"] = m[1]
		md["reason"] = "bad_credentials"
		if m[2] != "" {
			md["reason"] = "invalid_user"
		}
		if !addPort(md, m[5]) {
			return event.Event{}, false
		}
	case sshdInvalid.MatchString(msg):
		m := sshdInvalid.FindStringSubmatch(msg)
		// sshd logs "Invalid user" before the "Failed password for invalid user" of the
		// same attempt; a separate type keeps AUTH-001 from counting one attempt twice.
		typ, user, ip = "invalid_user", m[1], m[2]
		md["reason"] = "invalid_user"
		if m[3] != "" && !addPort(md, m[3]) {
			return event.Event{}, false
		}
	case sshdAccepted.MatchString(msg):
		m := sshdAccepted.FindStringSubmatch(msg)
		typ, user, ip = "authentication_success", m[2], m[3]
		md["method"] = m[1]
		if !addPort(md, m[4]) {
			return event.Event{}, false
		}
	default:
		return event.Event{}, false
	}

	ip, ok = normalizeIP(ip)
	if !ok {
		return event.Event{}, false
	}
	return event.Event{
		ID:        fmt.Sprintf("%s-%d", sshdSource, lineNo),
		Timestamp: ts,
		Source:    sshdSource,
		Type:      typ,
		Actor:     &event.Actor{Username: user},
		Network:   &event.Network{SourceIP: ip},
		Target:    &event.Target{Host: host},
		Metadata:  md,
	}, true
}

// splitTimestamp reads the leading timestamp and returns the rest of the line.
func (s *SSHD) splitTimestamp(line string) (time.Time, string, bool) {
	if line == "" {
		return time.Time{}, "", false
	}
	if line[0] >= '0' && line[0] <= '9' {
		tok, rest, ok := strings.Cut(line, " ")
		if !ok {
			return time.Time{}, "", false
		}
		ts, err := time.Parse(time.RFC3339, tok)
		return ts, rest, err == nil
	}
	if len(line) <= classicLen || line[classicLen] != ' ' {
		return time.Time{}, "", false
	}
	t, err := time.ParseInLocation(classicLayout, line[:classicLen], s.loc)
	if err != nil {
		return time.Time{}, "", false
	}
	ts := time.Date(s.year, t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, s.loc)
	// Feb 29 in a non-leap year would silently roll over to Mar 1.
	if ts.Month() != t.Month() {
		return time.Time{}, "", false
	}
	return ts, line[classicLen+1:], true
}

func addPort(md map[string]any, s string) bool {
	port, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return false
	}
	md["port"] = int(port)
	return true
}
