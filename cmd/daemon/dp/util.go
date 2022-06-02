package dp

import (
	"errors"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
	"os"
)

const (
	logEncryptKey     = "1234567a1234567b"
	checkFileTemplate = "/host/proc/%d/root/.tensor/dp.so"
)

func EncryptedLogErrMsg(msg, key, normalMsg string) {
	encryptedMsg, err := util.AesEncryptCBC([]byte(msg), []byte(key))
	if err != nil {
		// encrypted err,just log a simple msg
		logging.Get().Err(err).Msgf("%s", normalMsg)
	} else {
		logging.Get().Error().Msgf("%s", encryptedMsg)
	}
}

func IsInjected(processID int) (bool, error) {
	_, err := os.Stat(fmt.Sprintf(checkFileTemplate, processID))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			logging.Get().Debug().Int("processID", processID).Msg("not found injected file")
			return false, nil
		}
		logging.Get().Error().Msgf("Failed to check if process %d is injected: %v", processID, err)
		return false, err
	}

	return true, nil
}

func GetContainerPodInfo(pid int, npw *nodeinfo.NodePodsWatcher) (string, string, error) {
	podUID, err := k8s.GetPodIDFromProc(k8s.HostInfo{ProcPath: "/host/proc"}, pid)
	if err != nil {
		logging.Get().Error().Msgf("get pod info by containerID err:%v", err)
		return "", "", err
	}

	podInfo, err := npw.GetPodByUID(podUID)
	if err != nil {
		logging.Get().Error().Err(err).Msg("get pod info fail")
		return "", "", err
	}
	logging.Get().Debug().Msgf("generateEvent: %v", podInfo)

	return podInfo.Namespace, podUID, nil
}
