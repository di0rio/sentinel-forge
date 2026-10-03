// Package parser turns raw log lines into normalized events.
//
// Logs are untrusted input: lines are length-bounded, every pattern is
// anchored (and Go's regexp is linear-time), addresses are validated with
// net/netip, and malformed lines are counted and skipped, never fatal.
//
// Event IDs are derived from the source name and the line number, so parsing
// the same file twice yields identical events.
package parser

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"

	"github.com/di0rio/sentinel-forge/internal/event"
)

// MaxLineBytes is the longest line (terminator included) that is parsed.
const MaxLineBytes = 64 << 10

// Parser turns one log line into an event. lineNo is 1-based. ok is false
// for lines that are not events of interest, including malformed ones.
type Parser interface {
	Parse(line string, lineNo int) (ev event.Event, ok bool)
}

// Result is the outcome of reading a whole log.
type Result struct {
	Events  []event.Event
	Skipped int      // lines that are noise or could not be parsed
	Failed  []string // lines rejected before parsing, e.g. over MaxLineBytes
}

// ReadAll parses every line from r. Lines over MaxLineBytes are reported in
// Result.Failed and skipped; reading continues with the next line. A
// bufio.Scanner would stop for good on such a line (ErrTooLong), so a
// bufio.Reader is used instead.
func ReadAll(r io.Reader, p Parser) (Result, error) {
	var res Result
	br := bufio.NewReaderSize(r, MaxLineBytes)
	for n := 1; ; n++ {
		line, tooLong, err := readLine(br)
		if errors.Is(err, io.EOF) {
			return res, nil
		}
		if err != nil {
			return res, err
		}
		if tooLong {
			res.Failed = append(res.Failed, fmt.Sprintf("line %d: exceeds %d bytes", n, MaxLineBytes))
			continue
		}
		if ev, ok := p.Parse(strings.ToValidUTF8(line, "�"), n); ok {
			res.Events = append(res.Events, ev)
		} else {
			res.Skipped++
		}
	}
}

// readLine returns the next line without its terminator. A line longer than
// the reader's buffer is drained up to the next newline and reported as tooLong.
func readLine(br *bufio.Reader) (line string, tooLong bool, err error) {
	b, err := br.ReadSlice('\n')
	for errors.Is(err, bufio.ErrBufferFull) {
		tooLong = true
		_, err = br.ReadSlice('\n')
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return "", false, err
	}
	if tooLong {
		return "", true, nil
	}
	if errors.Is(err, io.EOF) && len(b) == 0 {
		return "", false, io.EOF
	}
	return strings.TrimRight(string(bytes.Clone(b)), "\r\n"), false, nil
}

// normalizeIP validates s as an IP address and returns its canonical form
// (no zone, IPv4-mapped IPv6 unmapped) so one host is always one group.
func normalizeIP(s string) (string, bool) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return "", false
	}
	return addr.WithZone("").Unmap().String(), true
}
