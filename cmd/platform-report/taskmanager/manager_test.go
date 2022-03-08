package taskmanager

import (
	"errors"
	"os"
	"testing"
)

func TestRemove(t *testing.T) {
	err := os.Remove("nonsense")
	t.Log(errors.Is(err, os.ErrNotExist))
}
