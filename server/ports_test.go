package server

import (
	"testing"
)

func TestIsPortAllowed(t *testing.T) {
	tests := []struct {
		name         string
		port         int
		allowedPorts string
		expected     bool
	}{
		{"Empty allowedPorts string", 8080, "", true},
		{"Port in single range", 8080, "8000-9000", true},
		{"Port at start of range", 8000, "8000-9000", true},
		{"Port at end of range", 9000, "8000-9000", true},
		{"Port outside of range", 7999, "8000-9000", false},
		{"Port in single port list", 9099, "8080,9099,10000", true},
		{"Port not in single port list", 8081, "8080,9099,10000", false},
		{"Port in mixed list (range)", 8500, "8000-9000,9099", true},
		{"Port in mixed list (single)", 9099, "8000-9000,9099", true},
		{"Port not in mixed list", 9098, "8000-9000,9099", false},
		{"Spaced list", 8080, " 8000 - 9000 , 9099 ", true},
		{"Invalid range", 8080, "8000-9000-10000", false},
		{"Invalid number", 8080, "abcd", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isPortAllowed(tt.port, tt.allowedPorts); got != tt.expected {
				t.Errorf("isPortAllowed(%d, %q) = %v; want %v", tt.port, tt.allowedPorts, got, tt.expected)
			}
		})
	}
}
