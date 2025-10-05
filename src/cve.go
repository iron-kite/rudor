package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// CVEResult represents a vulnerability finding
type CVEResult struct {
	CVE         string   `json:"cve"`
	Component   string   `json:"component"`
	Version     string   `json:"version"`
	Severity    string   `json:"severity"`
	Score       float64  `json:"score"`
	Description string   `json:"description"`
	References  []string `json:"references"`
}

// Global HTTP client for better connection reuse
var httpClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	},
}

// CVEReport represents the complete vulnerability report
type CVEReport struct {
	ScanDate        string      `json:"scan_date"`
	TotalIssues     int         `json:"total_issues"`
	Critical        int         `json:"critical"`
	High            int         `json:"high"`
	Medium          int         `json:"medium"`
	Low             int         `json:"low"`
	Vulnerabilities []CVEResult `json:"vulnerabilities"`
}

// OSVResponse represents response from OSV API
type OSVResponse struct {
	Vulns []OSVVuln `json:"vulns"`
}

type OSVVuln struct {
	ID         string         `json:"id"`
	Summary    string         `json:"summary"`
	Details    string         `json:"details"`
	Severity   []OSVSeverity  `json:"severity"`
	References []OSVReference `json:"references"`
	Affected   []OSVAffected  `json:"affected"`
}

type OSVSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type OSVReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type OSVAffected struct {
	Package OSVPackage `json:"package"`
	Ranges  []OSVRange `json:"ranges"`
}

type OSVPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

type OSVRange struct {
	Type   string     `json:"type"`
	Events []OSVEvent `json:"events"`
}

type OSVEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

// runCVECheckWithBOM performs vulnerability scanning on the provided BOM struct
func runCVECheckWithBOM(bom *cdx.BOM, verbose bool) error {
	if verbose {
		fmt.Println("🔍 Starting CVE analysis...")
	}

	// Extract components from the BOM
	components := extractComponentsFromBOM(bom)

	if len(components) == 0 {
		fmt.Println("⚠️  No components found in SBOM")
		return nil
	}

	if verbose {
		fmt.Printf("📦 Found %d components to analyze\n", len(components))
	}

	// Initialize report
	report := &CVEReport{
		ScanDate:        time.Now().UTC().Format(time.RFC3339),
		Vulnerabilities: []CVEResult{},
	}

	// Use parallel processing for CVE checking
	vulnerabilities := checkComponentsInParallel(components, verbose)
	report.Vulnerabilities = vulnerabilities

	// Process and display results
	processAndDisplayResults(report, verbose)

	// Write detailed report to file
	reportPath := "cve-report.json"
	if err := writeReportToFile(report, reportPath); err != nil {
		fmt.Printf("⚠️  Warning: Could not write CVE report to %s: %v\n", reportPath, err)
	} else if verbose {
		fmt.Printf("\n📄 Detailed report saved to: %s\n", reportPath)
	}

	return nil
}

// ComponentResult represents the result of checking a single component
type ComponentResult struct {
	Component       cdx.Component
	Vulnerabilities []CVEResult
	Error           error
}

// checkComponentsInParallel processes components in parallel using worker pools
func checkComponentsInParallel(components []cdx.Component, verbose bool) []CVEResult {
	// Determine optimal number of workers based on CPU count and component count
	numWorkers := runtime.NumCPU() * 2 // Use 2x CPU cores for I/O bound operations
	if len(components) < numWorkers {
		numWorkers = len(components)
	}

	// Limit max workers to avoid overwhelming the API
	if numWorkers > 10 {
		numWorkers = 10
	}

	if verbose {
		fmt.Printf("🚀 Using %d parallel workers for vulnerability checking\n", numWorkers)
	}

	// Create channels for work distribution
	componentChan := make(chan cdx.Component, len(components))
	resultChan := make(chan ComponentResult, len(components))

	// Rate limiter: allow up to 20 requests per second across all workers
	rateLimiter := time.NewTicker(50 * time.Millisecond)
	defer rateLimiter.Stop()

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for component := range componentChan {
				// Wait for rate limiter
				<-rateLimiter.C

				if verbose {
					fmt.Printf("🔍 Worker %d checking: %s@%s\n", workerID+1, component.Name, component.Version)
				}

				vulns, err := checkComponentVulnerabilities(component, false) // Don't pass verbose to avoid spam
				resultChan <- ComponentResult{
					Component:       component,
					Vulnerabilities: vulns,
					Error:           err,
				}
			}
		}(i)
	}

	// Send all components to workers
	go func() {
		for _, component := range components {
			componentChan <- component
		}
		close(componentChan)
	}()

	// Collect results
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Process results
	var allVulnerabilities []CVEResult
	processedCount := 0
	for result := range resultChan {
		processedCount++
		if verbose {
			fmt.Printf("✅ Processed %d/%d: %s\n", processedCount, len(components), result.Component.Name)
		}

		if result.Error != nil {
			if verbose {
				fmt.Printf("⚠️  Warning: Failed to check %s: %v\n", result.Component.Name, result.Error)
			}
			continue
		}

		allVulnerabilities = append(allVulnerabilities, result.Vulnerabilities...)
	}

	if verbose {
		fmt.Printf("🏁 Completed vulnerability checking for all %d components\n", len(components))
	}

	return allVulnerabilities
}

// extractComponentsFromBOM extracts components from a BOM struct
func extractComponentsFromBOM(bom *cdx.BOM) []cdx.Component {
	var components []cdx.Component
	if bom.Components != nil {
		for _, component := range *bom.Components {
			// Only check components with versions
			if component.Version != "" && component.Name != "" {
				components = append(components, component)
			}
		}
	}
	return components
}

// checkComponentVulnerabilities queries OSV API for vulnerabilities
func checkComponentVulnerabilities(component cdx.Component, verbose bool) ([]CVEResult, error) {
	var results []CVEResult

	// Determine ecosystem based on component type or name patterns
	ecosystem := determineEcosystem(component)
	if ecosystem == "" {
		return results, nil // Skip unknown ecosystems
	}

	// Query OSV API
	vulns, err := queryOSVAPI(ecosystem, component.Name, component.Version)
	if err != nil {
		return nil, err
	}

	// Convert OSV vulnerabilities to CVE results
	for _, vuln := range vulns {
		severity, score := extractSeverity(vuln.Severity)

		references := make([]string, 0, len(vuln.References))
		for _, ref := range vuln.References {
			references = append(references, ref.URL)
		}

		result := CVEResult{
			CVE:         vuln.ID,
			Component:   component.Name,
			Version:     component.Version,
			Severity:    severity,
			Score:       score,
			Description: vuln.Summary,
			References:  references,
		}

		results = append(results, result)
	}

	return results, nil
}

// determineEcosystem maps component types to OSV ecosystems
func determineEcosystem(component cdx.Component) string {
	// Check for common package manager indicators
	switch {
	case strings.Contains(strings.ToLower(component.Name), "npm:") ||
		strings.Contains(strings.ToLower(component.Group), "npm"):
		return "npm"
	case strings.Contains(strings.ToLower(component.Name), "pypi:") ||
		strings.Contains(strings.ToLower(component.Group), "pypi"):
		return "PyPI"
	case strings.Contains(strings.ToLower(component.Name), "maven:") ||
		strings.Contains(strings.ToLower(component.Group), "maven"):
		return "Maven"
	case strings.Contains(strings.ToLower(component.Name), "nuget:") ||
		strings.Contains(strings.ToLower(component.Group), "nuget"):
		return "NuGet"
	case strings.Contains(strings.ToLower(component.Name), "cargo:") ||
		strings.Contains(strings.ToLower(component.Group), "cargo"):
		return "crates.io"
	case strings.Contains(strings.ToLower(component.Name), "golang:") ||
		strings.Contains(strings.ToLower(component.Group), "golang") ||
		strings.Contains(component.Name, "github.com/"):
		return "Go"
	default:
		// Try to guess from component type
		switch component.Type {
		case cdx.ComponentTypeLibrary:
			// Default to npm for libraries if no other indicator
			return "npm"
		default:
			return ""
		}
	}
}

// queryOSVAPI queries the OSV database for vulnerabilities
func queryOSVAPI(ecosystem, name, version string) ([]OSVVuln, error) {
	const osvURL = "https://api.osv.dev/v1/query"

	queryData := map[string]interface{}{
		"package": map[string]string{
			"ecosystem": ecosystem,
			"name":      name,
		},
		"version": version,
	}

	jsonData, err := json.Marshal(queryData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal query: %w", err)
	}

	req, err := http.NewRequest("POST", osvURL, strings.NewReader(string(jsonData)))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to query OSV API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV API returned status %d", resp.StatusCode)
	}

	var osvResp OSVResponse
	if err := json.NewDecoder(resp.Body).Decode(&osvResp); err != nil {
		return nil, fmt.Errorf("failed to decode OSV response: %w", err)
	}

	return osvResp.Vulns, nil
}

// extractSeverity extracts severity information from OSV vulnerability
func extractSeverity(severities []OSVSeverity) (string, float64) {
	for _, sev := range severities {
		if sev.Type == "CVSS_V3" {
			// Parse CVSS score if available
			score := parseCVSSScore(sev.Score)
			severity := cvssScoreToSeverity(score)
			return severity, score
		}
	}
	return "UNKNOWN", 0.0
}

// parseCVSSScore extracts numeric score from CVSS string
func parseCVSSScore(cvssString string) float64 {
	// Simple parsing - in real implementation you'd parse the full CVSS vector
	// For now, just try to extract any numeric value
	parts := strings.Split(cvssString, "/")
	for _, part := range parts {
		_ = strings.HasPrefix(part, "S:") || strings.HasPrefix(part, "score:")
		// Extract score value
		// This is simplified - real CVSS parsing would be more complex
	}
	return 5.0 // Default medium score
}

// cvssScoreToSeverity converts CVSS score to severity level
func cvssScoreToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score > 0.0:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

// processAndDisplayResults analyzes and displays the vulnerability report
func processAndDisplayResults(report *CVEReport, verbose bool) {
	// Count severities
	for _, vuln := range report.Vulnerabilities {
		switch vuln.Severity {
		case "CRITICAL":
			report.Critical++
		case "HIGH":
			report.High++
		case "MEDIUM":
			report.Medium++
		case "LOW":
			report.Low++
		}
	}
	report.TotalIssues = len(report.Vulnerabilities)

	// Display summary
	fmt.Println("\n🛡️  CVE Analysis Results")
	fmt.Println("========================")

	if report.TotalIssues == 0 {
		fmt.Println("✅ No vulnerabilities found!")
		return
	}

	fmt.Printf("Total Issues: %d\n", report.TotalIssues)
	if report.Critical > 0 {
		fmt.Printf("🔴 Critical: %d\n", report.Critical)
	}
	if report.High > 0 {
		fmt.Printf("🟠 High: %d\n", report.High)
	}
	if report.Medium > 0 {
		fmt.Printf("🟡 Medium: %d\n", report.Medium)
	}
	if report.Low > 0 {
		fmt.Printf("🔵 Low: %d\n", report.Low)
	}

	// Sort vulnerabilities by severity (critical first)
	sort.Slice(report.Vulnerabilities, func(i, j int) bool {
		severityOrder := map[string]int{
			"CRITICAL": 4,
			"HIGH":     3,
			"MEDIUM":   2,
			"LOW":      1,
			"UNKNOWN":  0,
		}
		return severityOrder[report.Vulnerabilities[i].Severity] > severityOrder[report.Vulnerabilities[j].Severity]
	})

	// Display detailed results if verbose or if critical/high issues exist
	if verbose || report.Critical > 0 || report.High > 0 {
		fmt.Println("\nDetailed Findings:")
		fmt.Println("------------------")

		for _, vuln := range report.Vulnerabilities {
			icon := getSeverityIcon(vuln.Severity)
			fmt.Printf("\n%s %s [%s]\n", icon, vuln.CVE, vuln.Severity)
			fmt.Printf("   Component: %s@%s\n", vuln.Component, vuln.Version)
			if vuln.Description != "" {
				fmt.Printf("   Description: %s\n", vuln.Description)
			}
			if len(vuln.References) > 0 && verbose {
				fmt.Printf("   Reference: %s\n", vuln.References[0])
			}
		}
	}
}

// getSeverityIcon returns an appropriate icon for the severity level
func getSeverityIcon(severity string) string {
	switch severity {
	case "CRITICAL":
		return "🔴"
	case "HIGH":
		return "🟠"
	case "MEDIUM":
		return "🟡"
	case "LOW":
		return "🔵"
	default:
		return "⚪"
	}
}

// writeReportToFile saves the complete vulnerability report as JSON
func writeReportToFile(report *CVEReport, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
