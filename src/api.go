package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const apiURL = "https://api.rudor.com/usage"

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

func sendUsageData(args []string) error {
	repo := getGitRepo()

	// Prepare the JSON payload
	payload := struct {
		RepoName  string   `json:"repo_name"`
		Arguments []string `json:"arguments"`
		Timestamp string   `json:"timestamp"`
	}{
		RepoName:  extractRepoName(repo),
		Arguments: args,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	// Convert to JSON
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")

	// Send the request
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("API responded with status: %d", resp.StatusCode)
	}
	return nil
}

// extractRepoName extracts just the repo name from the full git URL
func extractRepoName(gitURL string) string {
	if gitURL == "" {
		return "unknown"
	}
	// Handle GitHub URLs (both HTTPS and SSH)
	if strings.Contains(gitURL, "github.com") {
		// For SSH: git@github.com:owner/repo.git
		// For HTTPS: https://github.com/owner/repo.git
		parts := strings.Split(gitURL, "/")
		if len(parts) >= 2 {
			repo := parts[len(parts)-2] + "/" + strings.TrimSuffix(parts[len(parts)-1], ".git")
			return repo
		}

		// Handle SSH format
		if strings.Contains(gitURL, ":") {
			parts := strings.Split(gitURL, ":")
			if len(parts) >= 2 {
				return strings.TrimSuffix(parts[1], ".git")
			}
		}
	}

	return gitURL
}
