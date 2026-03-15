package report

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/coff0xc/lobster-guard/pkg/utils"
	"github.com/fatih/color"
)

// PrintSummary prints a colored summary of scan results
func PrintSummary(results []*utils.ScanResult) {
	fmt.Println()
	fmt.Println(strings.Repeat("═", 76))
	color.New(color.FgCyan, color.Bold).Println("  SCAN SUMMARY")
	fmt.Println(strings.Repeat("═", 76))

	totalFindings := 0
	for _, r := range results {
		totalFindings += len(r.Findings)
	}

	for _, r := range results {
		r.Done()
		duration := r.EndAt.Sub(r.StartAt).Round(time.Millisecond)
		fmt.Printf("\n  Target: %s (scanned in %v)\n", r.Target.String(), duration)
		fmt.Println(strings.Repeat("─", 60))

		if len(r.Findings) == 0 {
			color.New(color.FgGreen).Println("  No findings.")
			continue
		}

		crit := r.CountBySeverity(utils.SevCritical)
		high := r.CountBySeverity(utils.SevHigh)
		med := r.CountBySeverity(utils.SevMedium)
		low := r.CountBySeverity(utils.SevLow)
		info := r.CountBySeverity(utils.SevInfo)

		fmt.Printf("  Findings: ")
		if crit > 0 {
			color.New(color.FgRed, color.Bold).Printf("%d CRITICAL  ", crit)
		}
		if high > 0 {
			color.New(color.FgRed).Printf("%d HIGH  ", high)
		}
		if med > 0 {
			color.New(color.FgYellow).Printf("%d MEDIUM  ", med)
		}
		if low > 0 {
			color.New(color.FgCyan).Printf("%d LOW  ", low)
		}
		if info > 0 {
			fmt.Printf("%d INFO  ", info)
		}
		fmt.Println()
		fmt.Println()

		for _, f := range r.Findings {
			f.Print()
		}
	}

	fmt.Println()
	fmt.Println(strings.Repeat("═", 76))
	if totalFindings == 0 {
		color.New(color.FgGreen, color.Bold).Println("  All clear — no security issues found.")
	} else {
		color.New(color.FgYellow, color.Bold).Printf("  Total: %d findings across %d target(s)\n", totalFindings, len(results))
	}
	fmt.Println(strings.Repeat("═", 76))
}

// WriteJSON writes scan results to a JSON file
func WriteJSON(results []*utils.ScanResult, path string) error {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write file: %w", err)
	}
	fmt.Printf("\n[*] JSON report saved to %s\n", path)
	return nil
}
