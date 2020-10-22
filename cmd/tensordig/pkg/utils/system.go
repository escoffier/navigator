package utils

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func GetTtyByPid(pid uint32) (string, error) {
	ttyStr, err := os.Readlink(filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10), "fd", "0"))
	if err != nil {
		return "", err
	}
	return strings.Replace(ttyStr, "/dev/", "", 1), nil
}

func GetExeByPid(pid uint32) (string, error) {
	exeStr, err := os.Readlink(filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10), "exe"))
	if err != nil {
		return "", err
	}
	return exeStr, nil
}
