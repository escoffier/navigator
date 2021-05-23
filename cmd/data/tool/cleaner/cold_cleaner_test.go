package cleaner

import (
	"context"
	"os"
	"path"
	"testing"
)

func TestColdCleaner(t *testing.T) {
	pwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	cleaner := NewColdCleaner(path.Join(pwd, "dump_test"))
	err = cleaner.Clean(context.TODO(), 0)
	if err != nil {
		t.Fatal(err)
	}
}
