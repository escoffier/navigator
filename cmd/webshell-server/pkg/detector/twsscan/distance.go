package twsscan

import (
	"math"

	"github.com/agnivade/levenshtein"
)

func distance(s1, s2 string) float64 {
	s := float64(levenshtein.ComputeDistance(s1, s2))
	return 1 - s/math.Max(float64(len(s1)), float64(len(s2)))
}
