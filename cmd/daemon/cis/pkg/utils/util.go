package utils

import (
	"fmt"
	"os"
	"strings"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/cis/pkg/check"
)

func GetSummaryTotals(controlsCollection []*check.Controls) check.Summary {
	var totalSummary check.Summary
	for _, controls := range controlsCollection {
		summary := controls.Summary
		totalSummary.Fail = totalSummary.Fail + summary.Fail
		totalSummary.Warn = totalSummary.Warn + summary.Warn
		totalSummary.Pass = totalSummary.Pass + summary.Pass
		totalSummary.Info = totalSummary.Info + summary.Info
	}
	return totalSummary
}

// ExitWithError takes terminates execution with error message.
func ExitWithError(err error) {
	fmt.Fprintf(os.Stderr, "\n%v\n", err)
	// flush before exit non-zero
	os.Exit(1)
}

func ParseSkipIds(skipIds string) map[string]bool {
	skipIdMap := make(map[string]bool, 0)
	if skipIds != "" {
		for _, id := range strings.Split(skipIds, ",") {
			skipIdMap[strings.Trim(id, " ")] = true
		}
	}
	return skipIdMap
}

func IsEmpty(str string) bool {
	return strings.TrimSpace(str) == ""
}
