package main

import "testing"

func TestClean(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"plain", "alice", "alice"},
		{"unicode text", "açaí 日本", "açaí 日本"},
		{"clear screen", "\x1b[2Jroot", "<U+001B>[2Jroot"},
		{"newline", "a\nb\r", "a<U+000A>b<U+000D>"},
		{"nul and bell", "a\x00\x07", "a<U+0000><U+0007>"},
		{"del", "\x7f", "<U+007F>"},
		{"C1 CSI", "\u009b31m", "<U+009B>31m"},
		{"bidi override", "evil\u202egpj.exe", "evil<U+202E>gpj.exe"},
		{"zero width", "ro\u200bot", "ro<U+200B>ot"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := clean(tt.in); got != tt.want {
				t.Fatalf("clean(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestCleanLinesKeepsLineBreaks(t *testing.T) {
	if got, want := cleanLines("a\x1b[0m\nb\tc"), "a<U+001B>[0m\nb<U+0009>c"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
