package kubemonitor

import (
	"testing"
)

func TestParseRules(t *testing.T) {
	err := parseRules()
	if err != nil {
		t.Errorf("parse rules error: %v", err)
	}
}
