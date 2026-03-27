package cmd

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/gemini-cli/tmproxy/common"
)

// RunPasswd generates a bcrypt hash for a password.
// It supports both interactive mode (prompting for password) and parameter mode (via --password flag).
// If --config flag is provided, it updates the ADMIN_PASSWORD_HASH in the config file.
func RunPasswd(args []string) {
	fs := flag.NewFlagSet("passwd", flag.ExitOnError)
	password := fs.String("password", "", "Password to hash (if empty, will prompt interactively)")
	configFile := fs.String("config", "", "Config file to update (optional)")
	fs.Parse(args)

	var pwd string
	if *password != "" {
		pwd = *password
	} else {
		// Interactive mode: prompt for password twice
		pwd = promptPassword()
	}

	// Generate bcrypt hash
	hash, err := common.HashPassword(pwd)
	if err != nil {
		fmt.Printf("Error hashing password: %v\n", err)
		os.Exit(1)
	}

	if *configFile != "" {
		// Update the config file
		if err := updateConfigPassword(*configFile, hash); err != nil {
			fmt.Printf("Error updating config file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Successfully updated ADMIN_PASSWORD_HASH in %s\n", *configFile)
	} else {
		fmt.Printf("Password hash: %s\n", hash)
		fmt.Println("Copy this value to ADMIN_PASSWORD_HASH in your config.json")
	}
}

// promptPassword interactively prompts the user for a password twice and confirms they match.
func promptPassword() string {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter password: ")
	pwd1, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("Error reading password: %v\n", err)
		os.Exit(1)
	}
	pwd1 = strings.TrimSpace(pwd1)

	if pwd1 == "" {
		fmt.Println("Password cannot be empty!")
		os.Exit(1)
	}

	fmt.Print("Confirm password: ")
	pwd2, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("Error reading password: %v\n", err)
		os.Exit(1)
	}
	pwd2 = strings.TrimSpace(pwd2)

	if pwd1 != pwd2 {
		fmt.Println("Passwords do not match!")
		os.Exit(1)
	}

	return pwd1
}

// updateConfigPassword updates the ADMIN_PASSWORD_HASH field in the config file.
func updateConfigPassword(configPath, hash string) error {
	// Read the config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse as generic map to preserve all fields
	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	// Update the password hash
	config["ADMIN_PASSWORD_HASH"] = hash

	// Write back to file
	newData, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(configPath, newData, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}