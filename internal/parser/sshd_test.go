package parser

import (
	"testing"
	"time"

	"github.com/di0rio/sentinel-forge/internal/event"
)

func sshdEvent(id string, ts time.Time, typ, user, ip string, md map[string]any) event.Event {
	return event.Event{
		ID:        id,
		Timestamp: ts,
		Source:    "sshd",
		Type:      typ,
		Actor:     &event.Actor{Username: user},
		Network:   &event.Network{SourceIP: ip},
		Target:    &event.Target{Host: "bastion01"},
		Metadata:  md,
	}
}

func TestSSHDParse(t *testing.T) {
	classic := time.Date(2026, 10, 3, 14, 32, 11, 0, time.UTC)
	tests := []struct {
		name string
		line string
		want *event.Event // nil: the line must be skipped
	}{
		{
			"failed password, valid user",
			"Oct  3 14:32:11 bastion01 sshd[1234]: Failed password for root from 203.0.113.45 port 51234 ssh2",
			ptr(sshdEvent("sshd-1", classic, "authentication_failure", "root", "203.0.113.45",
				map[string]any{"method": "password", "port": 51234, "reason": "bad_credentials"})),
		},
		{
			"failed password, invalid user",
			"Oct  3 14:32:11 bastion01 sshd[1234]: Failed password for invalid user admin from 203.0.113.45 port 51234 ssh2",
			ptr(sshdEvent("sshd-1", classic, "authentication_failure", "admin", "203.0.113.45",
				map[string]any{"method": "password", "port": 51234, "reason": "invalid_user"})),
		},
		{
			"failed keyboard-interactive",
			"Oct  3 14:32:11 bastion01 sshd[1234]: Failed keyboard-interactive/pam for root from 203.0.113.45 port 51234 ssh2",
			ptr(sshdEvent("sshd-1", classic, "authentication_failure", "root", "203.0.113.45",
				map[string]any{"method": "keyboard-interactive/pam", "port": 51234, "reason": "bad_credentials"})),
		},
		{
			"invalid user with port",
			"Oct  3 14:32:11 bastion01 sshd[1234]: Invalid user oracle from 203.0.113.45 port 40022",
			ptr(sshdEvent("sshd-1", classic, "invalid_user", "oracle", "203.0.113.45",
				map[string]any{"port": 40022, "reason": "invalid_user"})),
		},
		{
			"invalid user without port (older OpenSSH)",
			"Oct  3 14:32:11 bastion01 sshd[1234]: Invalid user oracle from 203.0.113.45",
			ptr(sshdEvent("sshd-1", classic, "invalid_user", "oracle", "203.0.113.45",
				map[string]any{"reason": "invalid_user"})),
		},
		{
			"accepted password",
			"Oct  3 14:32:11 bastion01 sshd[1234]: Accepted password for alice from 198.51.100.7 port 50022 ssh2",
			ptr(sshdEvent("sshd-1", classic, "authentication_success", "alice", "198.51.100.7",
				map[string]any{"method": "password", "port": 50022})),
		},
		{
			"accepted publickey with key fingerprint",
			"Oct  3 14:32:11 bastion01 sshd[1234]: Accepted publickey for deploy from 198.51.100.7 port 50022 ssh2: ED25519 SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
			ptr(sshdEvent("sshd-1", classic, "authentication_success", "deploy", "198.51.100.7",
				map[string]any{"method": "publickey", "port": 50022})),
		},
		{
			"ipv6 source",
			"Oct  3 14:32:11 bastion01 sshd[1234]: Failed password for root from 2001:db8::1 port 51234 ssh2",
			ptr(sshdEvent("sshd-1", classic, "authentication_failure", "root", "2001:db8::1",
				map[string]any{"method": "password", "port": 51234, "reason": "bad_credentials"})),
		},
		{
			"sshd-session binary and no pid",
			"Oct  3 14:32:11 bastion01 sshd-session: Failed password for root from 203.0.113.45 port 51234 ssh2",
			ptr(sshdEvent("sshd-1", classic, "authentication_failure", "root", "203.0.113.45",
				map[string]any{"method": "password", "port": 51234, "reason": "bad_credentials"})),
		},
		{
			"iso 8601 with fractional seconds and offset",
			"2026-10-03T11:32:11.123456-03:00 bastion01 sshd[1234]: Failed password for root from 203.0.113.45 port 51234 ssh2",
			ptr(sshdEvent("sshd-1", classic.Add(123456*time.Microsecond), "authentication_failure", "root", "203.0.113.45",
				map[string]any{"method": "password", "port": 51234, "reason": "bad_credentials"})),
		},
		{
			"iso 8601 UTC",
			"2026-10-03T14:32:11Z bastion01 sshd[1234]: Accepted publickey for deploy from 198.51.100.7 port 50022 ssh2",
			ptr(sshdEvent("sshd-1", classic, "authentication_success", "deploy", "198.51.100.7",
				map[string]any{"method": "publickey", "port": 50022})),
		},
		{
			// The username cannot spoof the source: the trailing "from <ip> port <n>" wins.
			"username containing a fake source",
			"Oct  3 14:32:11 bastion01 sshd[1234]: Failed password for invalid user x from 8.8.8.8 port 22 from 203.0.113.45 port 51234 ssh2",
			ptr(sshdEvent("sshd-1", classic, "authentication_failure", "x from 8.8.8.8 port 22", "203.0.113.45",
				map[string]any{"method": "password", "port": 51234, "reason": "invalid_user"})),
		},
		{"other sshd message", "Oct  3 14:32:11 bastion01 sshd[1234]: Connection closed by authenticating user root 203.0.113.45 port 51234 [preauth]", nil},
		{"other program", "Oct  3 14:32:11 bastion01 CRON[999]: pam_unix(cron:session): session opened for user root", nil},
		{"sudo mentioning sshd text", "Oct  3 14:32:11 bastion01 sudo: Failed password for root from 203.0.113.45 port 22 ssh2", nil},
		{"invalid ip", "Oct  3 14:32:11 bastion01 sshd[1234]: Failed password for root from 203.0.113.999 port 51234 ssh2", nil},
		{"hostname instead of ip", "Oct  3 14:32:11 bastion01 sshd[1234]: Failed password for root from evil.example.com port 51234 ssh2", nil},
		{"port out of range", "Oct  3 14:32:11 bastion01 sshd[1234]: Failed password for root from 203.0.113.45 port 99999 ssh2", nil},
		{"trailing garbage after ssh2", "Oct  3 14:32:11 bastion01 sshd[1234]: Failed password for root from 203.0.113.45 port 22 ssh2 extra", nil},
		{"impossible date", "Feb 30 14:32:11 bastion01 sshd[1234]: Failed password for root from 203.0.113.45 port 22 ssh2", nil},
		{"leap day in non-leap year", "Feb 29 14:32:11 bastion01 sshd[1234]: Failed password for root from 203.0.113.45 port 22 ssh2", nil},
		{"bad month", "Foo  3 14:32:11 bastion01 sshd[1234]: Failed password for root from 203.0.113.45 port 22 ssh2", nil},
		{"bad iso timestamp", "2026-13-03T14:32:11Z bastion01 sshd[1234]: Failed password for root from 203.0.113.45 port 22 ssh2", nil},
		{"zero timestamp", "0001-01-01T00:00:00Z bastion01 sshd[1234]: Failed password for root from 203.0.113.45 port 22 ssh2", nil},
		{"truncated line", "Oct  3 14:32:11 bastion01 sshd[1234]: Failed passw", nil},
		{"timestamp only", "Oct  3 14:32:11", nil},
		{"empty", "", nil},
		{"binary junk", "\x00\x01\x02\xff\xfe", nil},
	}
	p := NewSSHD(WithYear(2026))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := p.Parse(tt.line, 1)
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

func TestSSHDLocation(t *testing.T) {
	loc := time.FixedZone("BRT", -3*3600)
	p := NewSSHD(WithYear(2026), WithLocation(loc))
	got, ok := p.Parse("Oct  3 11:32:11 bastion01 sshd[1]: Failed password for root from 203.0.113.45 port 22 ssh2", 7)
	if !ok {
		t.Fatal("line must parse")
	}
	if want := time.Date(2026, 10, 3, 14, 32, 11, 0, time.UTC); !got.Timestamp.Equal(want) {
		t.Fatalf("timestamp = %s, want %s", got.Timestamp, want)
	}
	if got.ID != "sshd-7" {
		t.Fatalf("id = %q, want sshd-7", got.ID)
	}
}

func TestSSHDDefaultYearIsCurrent(t *testing.T) {
	got, ok := NewSSHD().Parse("Oct  3 14:32:11 bastion01 sshd[1]: Failed password for root from 203.0.113.45 port 22 ssh2", 1)
	if !ok {
		t.Fatal("line must parse")
	}
	// Compared against the clock on both sides of the call to survive New Year's Eve.
	if y := got.Timestamp.Year(); y != time.Now().UTC().Year() && y != time.Now().UTC().Year()-1 {
		t.Fatalf("year = %d, want the current year", y)
	}
}

func FuzzParseSSHD(f *testing.F) {
	for _, seed := range []string{
		"Oct  3 14:32:11 bastion01 sshd[1234]: Failed password for invalid user admin from 203.0.113.45 port 51234 ssh2",
		"Oct  3 14:32:11 bastion01 sshd[1234]: Invalid user oracle from 203.0.113.45 port 40022",
		"Oct  3 14:32:11 bastion01 sshd[1234]: Accepted publickey for deploy from 198.51.100.7 port 50022 ssh2: ED25519 SHA256:abc",
		"2026-10-03T14:32:11.123456+00:00 bastion01 sshd-session[1234]: Failed password for root from 2001:db8::1 port 22 ssh2",
		"Feb 29 00:00:00 h sshd: Invalid user x from 1.2.3.4",
		"0001-01-01T00:00:00Z h sshd: Invalid user x from 1.2.3.4",
		"",
	} {
		f.Add(seed)
	}
	p := NewSSHD(WithYear(2026))
	f.Fuzz(func(t *testing.T, line string) {
		if ev, ok := p.Parse(line, 1); ok {
			checkInvariants(t, ev)
		}
	})
}

func ptr[T any](v T) *T { return &v }
