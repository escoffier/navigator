package whitelist

import (
	"os"
	"testing"
)

func TestFileHashCrc32(t *testing.T) {
	var crc uint32
	path := "/usr/bin/ls"
	stat, err := os.Stat(path)
	if err != nil {
		t.Errorf("Failed to stat file: %v\n", err)
	}
	crc = FileHashCrc32(path, stat.Size())
	t.Logf("checksum: %X", crc)

}
