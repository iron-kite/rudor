package main

import (
	_ "embed"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	outputPath  string
	projectType string
	verbose     bool
	noCVE       bool
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "rudor",
		Short: "Simple SBOM generator using embedded cdxgen",
	}

	var generateCmd = &cobra.Command{
		Use:   "generate [path]",
		Short: "Generate SBOM for a project",
		Args:  cobra.MaximumNArgs(1),
		Run:   runGenerate,
	}

	generateCmd.Flags().StringVarP(&outputPath, "output", "o", "bom.json", "Output file path")
	generateCmd.Flags().StringVarP(&projectType, "type", "t", "", "Project type (auto-detected if not specified)")
	generateCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	generateCmd.Flags().BoolVarP(&noCVE, "no-cve", "n", false, "Disable CVE output")

	rootCmd.AddCommand(generateCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runGenerate(cmd *cobra.Command, args []string) {
	projectPath := "."
	if len(args) > 0 {
		projectPath = args[0]
	}

	// Generate SBOM and get the BOM struct
	bom, err := generateSBOM(projectPath, projectType, verbose)
	if err != nil {
		fmt.Printf("❌ Error: %v\n", err)
		os.Exit(1)
	}

	// Save the BOM to file
	if err := saveBOM(bom, outputPath, verbose); err != nil {
		fmt.Printf("❌ Error saving SBOM: %v\n", err)
		os.Exit(1)
	}

	// Run CVE check using the BOM struct
	if !noCVE {
		if err := runCVECheckWithBOM(bom, verbose); err != nil {
			fmt.Printf("⚠️  CVE check failed: %v\n", err)
		}
	}
}
