package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
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

// checkComponentVulnerabilities queries OSV API for vulnerabilities using PURL
func checkComponentVulnerabilities(component cdx.Component, verbose bool) ([]CVEResult, error) {
	var results []CVEResult

	// Use the existing PackageURL from the component
	if component.PackageURL == "" {
		return results, nil // Skip components without PURLs
	}

	purl := component.PackageURL

	// Step 1: Query OSV API for vulnerability IDs using PURL
	vulnIDs, err := queryOSVWithPURL(purl)
	if err != nil {
		return nil, err
	}

	// Step 2: Fetch detailed vulnerability information for each ID
	for _, vulnID := range vulnIDs {
		vulnDetail, err := getVulnerabilityDetails(vulnID)
		if err != nil {
			if verbose {
				fmt.Printf("⚠️  Warning: Failed to get details for %s: %v\n", vulnID, err)
			}
			continue
		}

		// Extract severity and score from detailed vulnerability data
		severity, score := extractSeverityFromDetail(vulnDetail)

		references := make([]string, 0, len(vulnDetail.References))
		for _, ref := range vulnDetail.References {
			references = append(references, ref.URL)
		}

		result := CVEResult{
			CVE:         vulnDetail.ID,
			Component:   component.Name,
			Version:     component.Version,
			Severity:    severity,
			Score:       score,
			Description: vulnDetail.Summary,
			References:  references,
		}

		results = append(results, result)
	}

	return results, nil
}

// queryOSVWithPURL queries OSV API using PURL to get vulnerability IDs
func queryOSVWithPURL(purl string) ([]string, error) {
	const osvURL = "https://api.osv.dev/v1/query"

	queryData := map[string]interface{}{
		"package": map[string]string{
			"purl": purl,
		},
	}

	jsonData, err := json.Marshal(queryData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal PURL query: %w", err)
	}

	req, err := http.NewRequest("POST", osvURL, strings.NewReader(string(jsonData)))
	if err != nil {
		return nil, fmt.Errorf("failed to create PURL request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to query OSV API with PURL: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV PURL API returned status %d", resp.StatusCode)
	}

	var osvResp OSVResponse
	if err := json.NewDecoder(resp.Body).Decode(&osvResp); err != nil {
		return nil, fmt.Errorf("failed to decode OSV PURL response: %w", err)
	}

	// Extract vulnerability IDs
	var vulnIDs []string
	for _, vuln := range osvResp.Vulns {
		vulnIDs = append(vulnIDs, vuln.ID)
	}

	return vulnIDs, nil
}

// getVulnerabilityDetails fetches detailed vulnerability information by ID
func getVulnerabilityDetails(vulnID string) (*OSVVuln, error) {
	url := fmt.Sprintf("https://api.osv.dev/v1/vulns/%s", vulnID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create vulnerability details request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get vulnerability details: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV vulnerability API returned status %d", resp.StatusCode)
	}

	// Read the entire response body into a byte slice
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %w", err)
	}

	// Convert the byte slice to a string
	bodyString := string(bodyBytes)

	var vulnDetail OSVVuln
	if err := json.NewDecoder(strings.NewReader(bodyString)).Decode(&vulnDetail); err != nil {
		return nil, fmt.Errorf("failed to decode vulnerability details: %w", err)
	}

	return &vulnDetail, nil
}

// extractSeverityFromDetail extracts the best available severity and score
func extractSeverityFromDetail(vuln *OSVVuln) (string, float64) {
	// Look for CVSS scores in order of preference (newest first)
	for _, sev := range vuln.Severity {
		switch {
		case strings.HasPrefix(sev.Score, "CVSS:3.0"):
			cvss, err := gocvss30.ParseVector(sev.Score)
			if err != nil {
				log.Fatal(err)
			}
			baseScore := cvss.BaseScore()
			rating, err := gocvss30.Rating(baseScore)
			if err != nil {
				rating = "UNKNOWN"
			}
			return rating, baseScore
		case strings.HasPrefix(sev.Score, "CVSS:3.1"):
			cvss, err := gocvss31.ParseVector(sev.Score)
			if err != nil {
				log.Fatal(err)
			}
			baseScore := cvss.BaseScore()
			rating, err := gocvss31.Rating(baseScore)
			if err != nil {
				rating = "UNKNOWN"
			}
			return rating, baseScore
		case strings.HasPrefix(sev.Score, "CVSS:4.0"):
			cvss, err := gocvss40.ParseVector(sev.Score)
			if err != nil {
				log.Fatal(err)
			}
			baseScore := cvss.Score()
			rating, err := gocvss40.Rating(baseScore)
			if err != nil {
				rating = "UNKNOWN"
			}
			return rating, baseScore
		}
	}

	return "UNKNOWN", 0.0
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
			fmt.Printf("\n%s %s [%s (%.2f)]\n", icon, vuln.CVE, vuln.Severity, vuln.Score)
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
