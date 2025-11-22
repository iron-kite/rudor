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

// OSVBatchRequest represents a batch query request
type OSVBatchRequest struct {
	Queries []OSVQuery `json:"queries"`
}

type OSVQuery struct {
	Package   OSVQueryPackage `json:"package"`
	PageToken string          `json:"page_token,omitempty"`
}

type OSVQueryPackage struct {
	PURL string `json:"purl"`
}

// OSVBatchResponse represents the batch query response
type OSVBatchResponse struct {
	Results []OSVBatchResult `json:"results"`
}

type OSVBatchResult struct {
	Vulns         []OSVVuln `json:"vulns"`
	NextPageToken string    `json:"next_page_token,omitempty"`
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

	// Use batch query for CVE checking
	vulnerabilities, err := checkComponentsWithBatch(components, verbose)
	if err != nil {
		return fmt.Errorf("failed to check components for vulnerabilities: %w", err)
	}
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

// checkComponentsWithBatch processes all components using OSV batch query API
func checkComponentsWithBatch(components []cdx.Component, verbose bool) ([]CVEResult, error) {
	if verbose {
		fmt.Printf("🚀 Using batch query for %d components\n", len(components))
	}

	// Build batch request
	var queries []OSVQuery
	var componentMap = make(map[int]cdx.Component)

	for _, component := range components {
		if component.PackageURL != "" {
			queries = append(queries, OSVQuery{
				Package: OSVQueryPackage{
					PURL: component.PackageURL,
				},
			})
			componentMap[len(queries)-1] = component
		}
	}

	if len(queries) == 0 {
		if verbose {
			fmt.Println("⚠️  No components with valid PURLs found")
		}
		return []CVEResult{}, nil
	}

	// Split queries into chunks to avoid API limits
	// OSV API recommends keeping batches reasonable in size
	const maxBatchSize = 1000
	var allBatchResults []OSVBatchResult

	for i := 0; i < len(queries); i += maxBatchSize {
		end := i + maxBatchSize
		if end > len(queries) {
			end = len(queries)
		}

		batchQueries := queries[i:end]

		if verbose {
			fmt.Printf("📤 Sending batch query %d-%d of %d components\n", i+1, end, len(queries))
		}

		// Query OSV API with batch request
		batchResults, err := queryOSVBatch(batchQueries, verbose)
		if err != nil {
			return nil, fmt.Errorf("batch query failed for queries %d-%d: %w", i+1, end, err)
		}

		allBatchResults = append(allBatchResults, batchResults.Results...)
	}

	if verbose {
		fmt.Printf("📥 Received batch results\n")
	}

	// Collect all unique vulnerability IDs
	vulnIDMap := make(map[string]bool)
	for _, result := range allBatchResults {
		for _, vuln := range result.Vulns {
			vulnIDMap[vuln.ID] = true
		}
	}

	if verbose {
		fmt.Printf("🔍 Fetching details for %d unique vulnerabilities\n", len(vulnIDMap))
	}

	// Fetch detailed information for all vulnerabilities in parallel
	vulnDetails := fetchVulnerabilityDetailsInParallel(vulnIDMap, verbose)

	// Map vulnerabilities back to components
	var allVulnerabilities []CVEResult
	for idx, result := range allBatchResults {
		component := componentMap[idx]

		for _, vuln := range result.Vulns {
			if detail, ok := vulnDetails[vuln.ID]; ok {
				severity, score := extractSeverityFromDetail(detail)

				references := make([]string, 0, len(detail.References))
				for _, ref := range detail.References {
					references = append(references, ref.URL)
				}

				cveResult := CVEResult{
					CVE:         detail.ID,
					Component:   component.Name,
					Version:     component.Version,
					Severity:    severity,
					Score:       score,
					Description: detail.Summary,
					References:  references,
				}

				allVulnerabilities = append(allVulnerabilities, cveResult)
			}
		}
	}

	if verbose {
		fmt.Printf("🏁 Completed vulnerability checking for all %d components\n", len(components))
	}

	return allVulnerabilities, nil
}

// fetchVulnerabilityDetailsInParallel fetches detailed vulnerability information in parallel
func fetchVulnerabilityDetailsInParallel(vulnIDMap map[string]bool, verbose bool) map[string]*OSVVuln {
	vulnDetails := make(map[string]*OSVVuln)
	var mu sync.Mutex

	// Convert map to slice
	var vulnIDs []string
	for id := range vulnIDMap {
		vulnIDs = append(vulnIDs, id)
	}

	if len(vulnIDs) == 0 {
		return vulnDetails
	}

	// Use worker pool for fetching details
	numWorkers := runtime.NumCPU() * 2
	if len(vulnIDs) < numWorkers {
		numWorkers = len(vulnIDs)
	}
	if numWorkers > 10 {
		numWorkers = 10
	}

	idChan := make(chan string, len(vulnIDs))
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for vulnID := range idChan {
				detail, err := getVulnerabilityDetails(vulnID)
				if err != nil {
					if verbose {
						fmt.Printf("⚠️  Warning: Failed to get details for %s: %v\n", vulnID, err)
					}
					continue
				}

				mu.Lock()
				vulnDetails[vulnID] = detail
				mu.Unlock()
			}
		}()
	}

	// Send IDs to workers
	for _, id := range vulnIDs {
		idChan <- id
	}
	close(idChan)

	// Wait for completion
	wg.Wait()

	return vulnDetails
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

// queryOSVBatch sends a batch query to OSV API and handles pagination
func queryOSVBatch(queries []OSVQuery, verbose bool) (*OSVBatchResponse, error) {
	const osvBatchURL = "https://api.osv.dev/v1/querybatch"

	var allResults []OSVBatchResult
	currentQueries := queries

	// Keep querying until no more next_page_tokens are returned
	for len(currentQueries) > 0 {
		batchRequest := OSVBatchRequest{
			Queries: currentQueries,
		}

		jsonData, err := json.Marshal(batchRequest)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal batch query: %w", err)
		}

		req, err := http.NewRequest("POST", osvBatchURL, strings.NewReader(string(jsonData)))
		if err != nil {
			return nil, fmt.Errorf("failed to create batch request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to query OSV batch API: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("OSV batch API returned status %d: %s", resp.StatusCode, string(bodyBytes))
		}

		var batchResp OSVBatchResponse
		if err := json.NewDecoder(resp.Body).Decode(&batchResp); err != nil {
			return nil, fmt.Errorf("failed to decode OSV batch response: %w", err)
		}

		// Collect results and check for pagination
		var nextQueries []OSVQuery
		for i, result := range batchResp.Results {
			// Add current result
			if i < len(allResults) {
				// Append to existing result
				allResults[i].Vulns = append(allResults[i].Vulns, result.Vulns...)
			} else {
				// Add new result
				allResults = append(allResults, result)
			}

			// Check if this query has more pages
			if result.NextPageToken != "" {
				if verbose {
					fmt.Printf("📚 Pagination detected for query %d, fetching next page\n", i+1)
				}
				// Create a new query with the page token
				queryWithToken := currentQueries[i]
				queryWithToken.PageToken = result.NextPageToken
				nextQueries = append(nextQueries, queryWithToken)
			}
		}

		// Update current queries for next iteration
		currentQueries = nextQueries
	}

	return &OSVBatchResponse{Results: allResults}, nil
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
		log.Fatalf("Error reading response body: %v", err)
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
