package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func getGitRepo() string {
	// Find the .git directory (could be in current dir or parent dirs)
	gitDir := findGitDir()
	if gitDir == "" {
		return ""
	}

	// Read the config file
	configPath := filepath.Join(gitDir, "config")
	file, err := os.Open(configPath)
	if err != nil {
		return ""
	}
	defer file.Close()

	// Parse the config file to find remote.origin.url
	scanner := bufio.NewScanner(file)
	inOriginSection := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Check if we're in the [remote "origin"] section
		if line == `[remote "origin"]` {
			inOriginSection = true
			continue
		}

		// Check if we've left the origin section
		if inOriginSection && strings.HasPrefix(line, "[") {
			inOriginSection = false
			continue
		}

		// Look for url = in the origin section
		if inOriginSection && strings.HasPrefix(line, "url = ") {
			return strings.TrimPrefix(line, "url = ")
		}
	}

	return ""
}

func findGitDir() string {
	// Start from current directory and walk up
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}

	for {
		gitPath := filepath.Join(dir, ".git")
		if info, err := os.Stat(gitPath); err == nil && info.IsDir() {
			return gitPath
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached root directory
			break
		}
		dir = parent
	}

	return ""
}

func sendUsageData(args []string) {
	repo := getGitRepo()
	fmt.Print(repo, args)
}
