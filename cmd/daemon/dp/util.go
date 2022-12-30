package dp

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/segmentio/kafka-go"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
)

const (
	checkFileTemplate = "/host/proc/%d/root/.tensor/dp.so"
	curFileTemplate   = "/tensor/dp.so"
)

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
	originFile, err := os.Open(fmt.Sprintf(checkFileTemplate, processID))
	if err != nil {
		logging.Get().Error().Msgf("Failed to open origin file: %v", err)
		return false, err
	}

	originMd5 := md5.New()

	_, err = io.Copy(originMd5, originFile)
	if err != nil {
		logging.Get().Error().Msgf("Failed to check if process %d is injected: %v", processID, err)
		return false, err
	}
	originMd5Str := hex.EncodeToString(originMd5.Sum(nil))
	curFile, err := os.Open(curFileTemplate)
	if err != nil {
		logging.Get().Error().Msgf("Failed to open cur file: %v", err)
		return false, err
	}
	curMd5 := md5.New()
	_, err = io.Copy(curMd5, curFile)
	if err != nil {
		logging.Get().Error().Msgf("Failed to check if process %d is injected: %v", processID, err)
		return false, err
	}
	curMd5Str := hex.EncodeToString(curMd5.Sum(nil))
	if originMd5Str != curMd5Str {
		logging.Get().Warn().Msg("injected file is not the same as current file")
		os.RemoveAll(fmt.Sprintf(checkFileTemplate, processID))
		return false, nil
	}

	return true, nil
}

func GetContainerPodInfo(podUID string, npw *nodeinfo.NodePodsWatcher, podResInfo *nodeinfo.PodResInfo) (model.DriftSupportInfo, error) {
	var supportInfo model.DriftSupportInfo
	podInfo, err := npw.GetPodByUID(podUID)
	if err != nil {
		logging.Get().Error().Err(err).Msg("get pod info fail")
		return model.DriftSupportInfo{}, err
	}
	supportInfo.Cluster = podInfo.ClusterKey
	supportInfo.Namespace = podInfo.Namespace

	resInfo, ok := podResInfo.GetPod(podInfo.Namespace, podInfo.Name)
	if !ok {
		logging.Get().Error().Msgf("get pod res info fail, pod:%s/%s", podInfo.Namespace, podInfo.Name)
		return supportInfo, errors.New("get pod res info fail")
	}
	supportInfo.ResourceName = resInfo.Name
	supportInfo.ResourceKind = resInfo.Kind

	logging.Get().Trace().Str("return info:", fmt.Sprintf("%v", supportInfo)).Msg("")
	return supportInfo, nil
}

func Send2Kafka(mqWrite mq.Writer, topicStr string, msg []byte) error {
	return mqWrite.Write(
		context.Background(), topicStr, kafka.Message{
			Topic: topicStr,
			Key:   []byte("support resource info"),
			Value: msg,
		})
}
