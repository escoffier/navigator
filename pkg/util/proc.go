package util

import (
	"fmt"
	"os"
	"strings"
)

func ProcessName(pid int32, inContainer bool) (string, error) {
	var procDir string
	if inContainer {
		procDir = "/host/proc"
	} else {
		procDir = "/proc"
	}

	// check if /proc/pid exist
	exist := PathExists(fmt.Sprintf("%s/%d", procDir, pid))
	if !exist {
		return "", fmt.Errorf("pid not exist")
	}

	var contents string
	contents, err := os.Readlink(fmt.Sprintf("%s/%d/exe", procDir, pid))
	if err != nil {
		return "", err
	}

	name := strings.TrimSuffix(string(contents), "\n")

	return name, nil
}
