package server

import (
	"sort"
	"testing"
)

func TestParseAllowedPorts(t *testing.T) {
	tests := []struct {
		name         string
		allowedPorts string
		expected     []int
	}{
		{"Empty string", "", []int{}},
		{"Single port", "8080", []int{8080}},
		{"Simple range", "8000-8002", []int{8000, 8001, 8002}},
		{"Mixed list", "80,8080-8081,9000", []int{80, 8080, 8081, 9000}},
		{"Whitespace", " 80 , 8080 - 8081 , 9000 ", []int{80, 8080, 8081, 9000}},
		{"Invalid range format", "8000-", []int{}},                                                                   // Invalid parts are skipped
		{"Invalid number in range", "8000-abc", []int{}},                                                             // Invalid parts are skipped
		{"Invalid single port", "xyz", []int{}},                                                                      // Invalid parts are skipped
		{"Overlapping ranges", "100-105,103-108", []int{100, 101, 102, 103, 104, 105, 103, 104, 105, 106, 107, 108}}, // Duplicates are expected, as it just appends
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAllowedPorts(tt.allowedPorts)

			if err != nil {
				t.Errorf("parseAllowedPorts() unexpected error = %v", err)
				return
			}

			// Sort both slices before comparison to handle order differences
			sort.Ints(got)
			sort.Ints(tt.expected)

			if len(got) != len(tt.expected) {
				t.Errorf("parseAllowedPorts() got = %v, want %v", got, tt.expected)
				return
			}
			for i := range got {
				if got[i] != tt.expected[i] {
					t.Errorf("parseAllowedPorts() got = %v, want %v", got, tt.expected)
					break
				}
			}
		})
	}
}
