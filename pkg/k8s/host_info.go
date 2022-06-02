package k8s

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"gitlab.com/security-rd/go-pkg/logging"
)

var mountInfoPathTemplate = "%s/%d/mountinfo"

type HostInfo struct {
	ProcPath string
}

func GetPodIDFromProc(hi HostInfo, pid int) (string, error) {
	procPath := fmt.Sprintf(mountInfoPathTemplate, hi.ProcPath, pid)
	fp, err := os.OpenFile(procPath, os.O_RDONLY, 0444)
	if err != nil {
		return "", err
	}
	defer fp.Close()
	podID := ""
	buf := bufio.NewReader(fp)

	for {
		line, _, err := buf.ReadLine()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		infoList := strings.Split(string(line), "/")
		for index, s := range infoList {
			if s == "kubelet" {
				logging.Get().Debug().Msgf("index:%v, s:%v", index, s)
				podID = infoList[index+2]
				break
			}
		}
	}

	if len(podID) <= 0 {
		err = fmt.Errorf("can't find pod id from pid: %d", pid)
	}
	return podID, err

}
