package server

import (
	"strconv"
	"strings"
)

// isPortAllowed checks if a given port is within the ranges specified in the allowedPorts string.
// The string can be a comma-separated list of individual ports or ranges (e.g., "8000-9000,9099").
func isPortAllowed(port int, allowedPorts string) bool {
	if allowedPorts == "" {
		return true // If not configured, all ports are allowed
	}

	parts := strings.Split(allowedPorts, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			// This is a range
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				continue // Invalid range
			}
			start, err1 := strconv.Atoi(rangeParts[0])
			end, err2 := strconv.Atoi(rangeParts[1])
			if err1 != nil || err2 != nil {
				continue // Invalid number in range
			}
			if port >= start && port <= end {
				return true
			}
		} else {
			// This is a single port
			allowedPort, err := strconv.Atoi(part)
			if err != nil {
				continue // Invalid port number
			}
			if port == allowedPort {
				return true
			}
		}
	}

	return false
}
