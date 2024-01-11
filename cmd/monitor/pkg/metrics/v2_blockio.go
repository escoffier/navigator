package metrics

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func readIoStats(path string) []*IOEntry {
	// more details on the io.stat file format: https://www.kernel.org/doc/Documentation/cgroup-v2.txt
	var usage []*IOEntry
	fpath := filepath.Join(path, "io.stat")
	currentData, err := os.ReadFile(fpath)
	if err != nil {
		return usage
	}
	entries := strings.Split(string(currentData), "\n")

	for _, entry := range entries {
		parts := strings.Split(entry, " ")
		if len(parts) < 2 {
			continue
		}
		majmin := strings.Split(parts[0], ":")
		if len(majmin) != 2 {
			continue
		}
		major, err := strconv.ParseUint(majmin[0], 10, 0)
		if err != nil {
			return usage
		}
		minor, err := strconv.ParseUint(majmin[1], 10, 0)
		if err != nil {
			return usage
		}
		parts = parts[1:]
		ioEntry := IOEntry{
			Major: major,
			Minor: minor,
		}
		for _, s := range parts {
			keyPairValue := strings.Split(s, "=")
			if len(keyPairValue) != 2 {
				continue
			}
			v, err := strconv.ParseUint(keyPairValue[1], 10, 0)
			if err != nil {
				continue
			}
			switch keyPairValue[0] {
			case "rbytes":
				ioEntry.Rbytes = v
			case "wbytes":
				ioEntry.Wbytes = v
			case "rios":
				ioEntry.Rios = v
			case "wios":
				ioEntry.Wios = v
			}
		}
		usage = append(usage, &ioEntry)
	}
	return usage
}

type IOEntry struct {
	Major  uint64 `protobuf:"varint,1,opt,name=major,proto3" json:"major,omitempty"`
	Minor  uint64 `protobuf:"varint,2,opt,name=minor,proto3" json:"minor,omitempty"`
	Rbytes uint64 `protobuf:"varint,3,opt,name=rbytes,proto3" json:"rbytes,omitempty"`
	Wbytes uint64 `protobuf:"varint,4,opt,name=wbytes,proto3" json:"wbytes,omitempty"`
	Rios   uint64 `protobuf:"varint,5,opt,name=rios,proto3" json:"rios,omitempty"`
	Wios   uint64 `protobuf:"varint,6,opt,name=wios,proto3" json:"wios,omitempty"`
}
