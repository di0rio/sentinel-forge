package event

import "testing"

func TestIsField(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"type", true},
		{"network.sourceIp", true},
		{"metadata.status", true},
		{"metadata.user_agent", true},
		{"metadata.http.status-code", true},
		{"metadata.", false},
		{"metadata", false},
		{"metadata.a b", false},
		{"metadata.x\x1b[2J", false},
		{"metadata.a\nb", false},
		{"metadata.é", false},
		{"process.cmdline", false},
	}
	for _, tt := range tests {
		if got := IsField(tt.path); got != tt.want {
			t.Errorf("IsField(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}
