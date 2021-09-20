package cleaner

import (
	"context"
	"os"
	"path"
	"testing"

	"gitlab.com/piccolo_su/vegeta/cmd/data/def"
)

func TestColdCleaner(t *testing.T) {
	pwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	cleaner := NewColdCleaner(path.Join(pwd, "dump_test"))
	err = cleaner.Clean(context.TODO(), &def.CleanArg{
		DaysOffset: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
}
