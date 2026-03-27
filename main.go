package main

import (
	"fmt"
	"os"

	"github.com/gemini-cli/tmproxy/cmd"
	"github.com/gemini-cli/tmproxy/client"
	"github.com/gemini-cli/tmproxy/server"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	mode := os.Args[1]
	args := os.Args[2:]

	switch mode {
	case "server":
		server.Run(args)
	case "client":
		client.Run(args)
	case "passwd":
		cmd.RunPasswd(args)
	case "config":
		cmd.RunConfig(args)
	default:
		fmt.Printf("Unknown mode: %s\n", mode)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: tmproxy <command> [options]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  server   Start the proxy server")
	fmt.Println("  client   Start the proxy client")
	fmt.Println("  passwd   Generate password hash or update config file")
	fmt.Println("  config   Generate configuration file")
}
