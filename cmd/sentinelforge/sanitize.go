package main

import (
	"fmt"
	"strings"
	"unicode"
)

// clean makes untrusted text safe to print on a terminal. Event fields come
// from logs an attacker can write to (an sshd username may carry "\x1b[2J"),
// and rule files are untrusted too. Control characters (C0, DEL, C1) and
// invisible format characters (bidi overrides, zero-width) would let that text
// redraw the screen, hide output or reorder it, so they are shown as <U+XXXX>.
// Newlines are escaped as well: a value never spans or forges a line.
func clean(s string) string {
	if !strings.ContainsFunc(s, unsafeRune) {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if unsafeRune(r) {
			fmt.Fprintf(&b, "<U+%04X>", r)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// cleanLines is clean for text that is legitimately multi-line, such as an
// error that joins several messages: line breaks stay, everything else is escaped.
func cleanLines(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = clean(l)
	}
	return strings.Join(lines, "\n")
}

func unsafeRune(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }
