package utils

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/cis/pkg/check"
)

var (
	// Print colors
	colors = map[check.State]*color.Color{
		check.PASS: color.New(color.FgGreen),
		check.FAIL: color.New(color.FgRed),
		check.WARN: color.New(color.FgYellow),
		check.INFO: color.New(color.FgBlue),
	}
)

// ColorPrint outputs the state in a specific colour, along with a message string
func ColorPrint(state check.State, s string) {
	colors[state].Printf("[%s] ", state)
	fmt.Printf("%s", s)
}

// PrettyPrint outputs the results to stdout in human-readable format
func PrettyPrint(r *check.Controls, summary check.Summary, noResults, includeTestOutput, noRemediations, noSummary bool) {
	// Print check results.
	if !noResults {
		ColorPrint(check.INFO, fmt.Sprintf("%s %s\n", r.ID, r.Text))
		for _, g := range r.Groups {
			ColorPrint(check.INFO, fmt.Sprintf("%s %s\n", g.ID, g.Text))
			for _, c := range g.Checks {
				ColorPrint(c.State, fmt.Sprintf("%s %s\n", c.ID, c.Text))

				if includeTestOutput && c.State == check.FAIL && len(c.ActualValue) > 0 {
					printRawOutput(c.ActualValue)
				}
			}
		}

		fmt.Println()
	}

	// Print remediations.
	if !noRemediations && (summary.Fail > 0 || summary.Warn > 0 || summary.Info > 0) {
		colors[check.WARN].Printf("== Remediations %s ==\n", r.Type)
		for _, g := range r.Groups {
			for _, c := range g.Checks {
				if c.State == check.FAIL {
					fmt.Printf("%s %s\n", c.ID, c.Remediation)
				}
				if c.State == check.WARN {
					// Print the error if test failed due to problem with the audit command
					if c.Reason != "" && c.Type != check.MANUAL {
						fmt.Printf("%s audit test did not run: %s\n", c.ID, c.Reason)
					} else {
						fmt.Printf("%s %s\n", c.ID, c.Remediation)
					}
				}
			}
		}
		fmt.Println()
	}

	// Print summary setting output color to highest severity.
	if !noSummary {
		PrintSummary(summary, string(r.Type))
	}
}

func PrintSummary(summary check.Summary, sectionName string) {
	var res check.State
	if summary.Fail > 0 {
		res = check.FAIL
	} else if summary.Warn > 0 {
		res = check.WARN
	} else {
		res = check.PASS
	}

	colors[res].Printf("== Summary %s ==\n", sectionName)
	fmt.Printf("%d checks PASS\n%d checks FAIL\n%d checks WARN\n%d checks INFO\n\n",
		summary.Pass, summary.Fail, summary.Warn, summary.Info,
	)
}

func printRawOutput(output string) {
	for _, row := range strings.Split(output, "\n") {
		fmt.Println(fmt.Sprintf("\t %s", row))
	}
}
