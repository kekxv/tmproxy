package server

import (
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"
)

// parseAllowedPorts takes a string like "8000-9000,9099" and returns a slice of all individual allowed ports.
func parseAllowedPorts(allowedPorts string) ([]int, error) {
	if allowedPorts == "" {
		return nil, nil // No ports configured, return empty list and no error
	}

	var ports []int
	parts := strings.Split(allowedPorts, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				continue // Invalid range
			}
			start, err1 := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err1 != nil || err2 != nil {
				continue // Invalid number in range
			}
			for i := start; i <= end; i++ {
				ports = append(ports, i)
			}
		} else {
			allowedPort, err := strconv.Atoi(part)
			if err != nil {
				continue // Invalid port number
			}
			ports = append(ports, allowedPort)
		}
	}
	return ports, nil
}

// findAvailablePort finds an available port from the allowed list.
// It locks the server's mutex to safely access shared resources.
func (s *Server) findAvailablePort() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	allowedPorts, err := parseAllowedPorts(s.config.ALLOWED_PORTS)
	if err != nil {
		return 0, err
	}

	if len(allowedPorts) == 0 {
		return 0, fmt.Errorf("allowed ports list is empty")
	}

	usedPorts := make(map[int]bool)
	for _, client := range s.clients {
		client.mu.Lock()
		for _, forward := range client.Forwards {
			usedPorts[forward.REMOTE_PORT] = true
		}
		client.mu.Unlock()
	}

	// Shuffle the allowed ports to get a random one, not always the first one.
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	r.Shuffle(len(allowedPorts), func(i, j int) {
		allowedPorts[i], allowedPorts[j] = allowedPorts[j], allowedPorts[i]
	})

	for _, port := range allowedPorts {
		if !usedPorts[port] {
			// Check if the port is actually free on the system.
			ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
			if err == nil {
				ln.Close()
				return port, nil
			}
		}
	}

	return 0, fmt.Errorf("no available ports in the allowed range")
}
