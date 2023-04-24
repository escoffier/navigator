package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseSkipIds(t *testing.T) {
	skipMap := ParseSkipIds("4.12,4.13,5")
	_, fourTwelveExists := skipMap["4.12"]
	_, fourThirteenExists := skipMap["4.13"]
	_, fiveExists := skipMap["5"]
	_, other := skipMap["G1"]
	assert.True(t, fourThirteenExists)
	assert.True(t, fourTwelveExists)
	assert.True(t, fiveExists)
	assert.False(t, other)
}
