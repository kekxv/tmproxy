package main

import (
	"fmt"
	"os"

	"github.com/gemini-cli/tmproxy/client"
	"github.com/gemini-cli/tmproxy/server"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: tmproxy <server|client> [options]")
		os.Exit(1)
	}

	mode := os.Args[1]
	args := os.Args[2:]

	switch mode {
	case "server":
		server.Run(args)
	case "client":
		client.Run(args)
	default:
		fmt.Printf("Unknown mode: %s\n", mode)
		fmt.Println("Usage: tmproxy <server|client> [options]")
		os.Exit(1)
	}
}
