package twsscan

import (
	"fmt"
	"testing"
)

func (f *rawFile) String() string {
	return fmt.Sprintf(`{"fileName": %s, "content": %s}`, f.fileName, f.content)
}

func TestFuzzData(t *testing.T) {
	t.Log(DefaultFuzzData)
}

func TestHashData(t *testing.T) {
	t.Log(DefaultHashDataMap)
}
