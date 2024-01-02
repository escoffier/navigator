package assets

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"
	"sync"
	"time"

	json "github.com/json-iterator/go"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/container"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/cmd/config"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/services/helper"
	consts2 "gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"

	"github.com/segmentio/kafka-go"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"

	_ "gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/container/containerd"
	_ "gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/container/crio"
	_ "gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/container/docker"
	_ "gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/container/nsenter"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/services"
	types2 "gitlab.com/piccolo_su/vegeta/cmd/node-image/services/types"
	"gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

const (
	defaultReportInterval = 600
)

type SendAssetManager struct {
	sync.RWMutex
	Runtime         container.Runtime
	err             error
	mqWriter        mq.Writer
	initConfig      config.Config                 // init config load from yaml
	nodeImageConfig imagesecModel.ImageScanConfig // dynamic config synced from console
	subscribeChan   <-chan interface{}
	Log             *scannerUtils.LogEvent
}

func init() {
	err := services.RegisterService(NewSendAssetManager())
	if err != nil {
		logging.Get().Err(err).Msg("failed to register image asset manager service")
		return
	}
	logging.Get().Info().Msg("register image asset manager service ok")
}

func NewSendAssetManager() *SendAssetManager {
	return &SendAssetManager{
		RWMutex:         sync.RWMutex{},
		Runtime:         nil,
		err:             nil,
		mqWriter:        nil,
		initConfig:      config.Config{},
		nodeImageConfig: imagesecModel.ImageScanConfig{},
		subscribeChan:   nil,
		Log: scannerUtils.NewLogEvent(
			scannerUtils.WithModule("nodeImage"),
			scannerUtils.WithSubModule("SendAsset")),
	}
}

func (s *SendAssetManager) Type() consts.ServiceType {
	return consts.TypeServiceImageAsset
}

func (s *SendAssetManager) PreRun(cfg config.Config, nc imagesecModel.ImageScanConfig, bs *util.BroadcastServer) error {
	// copy config
	s.Log = scannerUtils.NewLogEvent(scannerUtils.WithModule("nodeImage"), scannerUtils.WithSubModule("SendAsset"))
	s.initConfig = cfg
	s.nodeImageConfig = nc

	// create Runtime cli
	r, err := container.CreateRuntimeCli()
	if err != nil {
		s.err = err
		s.Log.Err(err).Msg("failed to create Runtime cli")
		return err
	}
	s.Runtime = r

	// create msg que cli
	mqWriter, err := mq.GetClientFactory().Writer(context.Background())
	if err != nil {
		s.err = err
		s.Log.Err(err).Msg("failed to create mq writer")
		return err
	}
	s.mqWriter = mqWriter

	// subscribe notify
	s.subscribeChan = bs.Subscribe(string(consts.TypeServiceImageAsset))

	s.Log.Info().Msg("image asset manager pre run ok")

	return nil
}

func (s *SendAssetManager) updateNodeImageConfig(cfg imagesecModel.ImageScanConfig) {
	s.Lock()
	defer s.Unlock()
	s.nodeImageConfig = cfg
}

func (s *SendAssetManager) handleNotifyEvent() {
	for {
		select {
		case item := <-s.subscribeChan:
			switch typed := item.(type) {
			case types2.NotifyEvent:
				event := item.(types2.NotifyEvent)
				if event.Type == consts.NotifyEventTypeConfigModified {
					s.Log.Debug().Interface("event", event).Msg("recv config modified event,copy")

					// copy node image config
					s.updateNodeImageConfig(event.NodeImageConfig)
					continue
				}
				s.Log.Debug().Interface("event", event).Msg("image asset ignore irrelevant event")
			default:
				logging.Get().Error().Msgf("subscribe msg type err.%v", typed)
			}
		}
	}
}

func (s *SendAssetManager) SendAsset(ctx context.Context) {

	sysInfo := s.GetNodeSysInfo(ctx)

	s.Log.Debug().Interface("sysInfo", sysInfo).Msg("get node sys info")

	ticker := time.NewTicker(time.Duration(s.getReportInterval()) * time.Second)
	defer ticker.Stop()
	batchSize := int(s.initConfig.ReportConfig.BatchSize)
	for {
		images, err := s.Runtime.ListImages()
		if err != nil {
			s.Log.Err(err).Msg("failed to list images")
			continue
		}
		s.Log.Debug().Int("imageCount", len(images)).Msg("found node images")
		images = s.filterImage(images)
		s.Log.Debug().Int("imageCount", len(images)).Msg("found node images and filter image")

		versionReport := imagesec.ReportDBVersion{AviraDBVersion: helper.GetAviraDBVersion().WorkVersion.Version}
		for i := 0; i < len(images); i = i + batchSize {
			batch := images[i:util.MinInt(i+batchSize, len(images))]
			if err := s.sendAssetHelp(context.Background(), batch, sysInfo, versionReport); err != nil {
				s.Log.Err(err).Msg("send image to kafka")
				continue
			}
			s.Log.Info().Msg("send image to kafka succeed")
		}
		ticker.Reset(time.Duration(s.getReportInterval()) * time.Second)
		<-ticker.C
	}
}

func (s *SendAssetManager) sendAssetHelp(ctx context.Context, images []container.ImageSummary, sysInfo *SysInfo,
	versionReport imagesec.ReportDBVersion) error {
	report := &imagesec.NodeReport{
		UUID: util.GenerateUUIDHex(),
		NodeInfo: imagesec.NodeInfo{
			ClusterKey: sysInfo.ClusterKey,
			Ip:         sysInfo.HostIP,
			HostName:   sysInfo.HostName,
		},
		NodeImages:      make([]imagesec.ImageMeta, 0),
		ReportedAt:      time.Now().UnixMilli(),
		ReportDBVersion: versionReport,
	}

	for i := range images {

		ima := images[i]

		detail, err := s.Runtime.GetImageInspect(ima.Namespace, ima.ID)
		if err != nil {
			s.Log.Err(err).Interface("repoTags", ima.RepoTags).Msg("failed to inspect ima")
			continue
		}

		history, err := s.Runtime.ImageHistory(ima.Namespace, ima.ID)
		if err != nil {
			s.Log.Err(err).Interface("repoTags", ima.RepoTags).Msg("failed to get ima history")
			continue
		}

		imageMeta := transformImageInfo(ima, detail, history)

		report.NodeImages = append(report.NodeImages, imageMeta)
	}

	err := s.SendToMq(ctx, report)
	return err
}

func (s *SendAssetManager) Run() error {
	s.Log.Info().Msg("node image asset service starting")

	// handle notify
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("handleNotifyEvent panic: %v. Stack: %s", r, debug.Stack())
			}
		}()
		s.handleNotifyEvent()
	}()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("SendImage panic: %v. Stack: %s", r, debug.Stack())
			}
		}()
		s.SendAsset(context.Background())
	}()

	return nil
}

func (s *SendAssetManager) SendToMq(ctx context.Context, report *imagesec.NodeReport) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.getMqTimeout())*time.Second)
	defer cancel()
	msg, err := json.Marshal(report)
	if err != nil {
		return err
	}
	msg = scannerUtils.ZipByteSlice(msg)
	key := fmt.Sprintf("%s/node-report", report.NodeInfo.ClusterKey)
	err = s.mqWriter.Write(ctx, consts2.NodeImageTopic, kafka.Message{
		Key:   []byte(key),
		Value: msg,
	})
	if err != nil {
		return err
	}

	s.Log.Debug().Str("report", report.LogStr()).Msg("send node image to kafka")
	s.Log.Info().Int("imageCnt", len(report.NodeImages)).Msg("send node image to kafka")
	return nil
}

func transformImageInfo(ns container.ImageSummary, detail container.ImageInspect,
	history []container.HistoryResponseItem) imagesec.ImageMeta {
	me := imagesec.ImageMeta{
		Namespace: ns.Namespace,
		ImageId:   detail.ID,
		RepoTags:  ns.RepoTags,
		Digests:   ns.RepoDigests,
		Size:      detail.Size,
		Created:   detail.Created,
		ENVS:      detail.Env,
		User:      detail.User,
	}

	for _, v := range history {
		l := imagesec.Layer{
			Comment:   v.Comment,
			Created:   v.Created,
			CreatedBy: v.CreatedBy,
			Digest:    v.ID,
			Size:      v.Size,
		}
		me.Layers = append(me.Layers, l)
	}
	return me
}

type SysInfo struct {
	HostName   string
	HostIP     string
	ClusterKey string
}

func (s *SendAssetManager) GetNodeSysInfo(ctx context.Context) *SysInfo {
	info := &SysInfo{}

	// get node name
	hostName := os.Getenv("MY_NODE_NAME")
	if hostName == "" {
		hostName = "Unknown"
	}
	info.HostName = hostName

	// node ip
	hostIP := os.Getenv("MY_HOST_IP")
	if hostIP == "" {
		hostIP = "Unknown"
	}
	info.HostIP = hostIP

	// get cluster key
	clusterAddr := os.Getenv("CLUSTER_MANAGER_URL")
	if clusterAddr == "" {
		logging.Get().Error().Msg("env CLUSTER_MANAGER_URL not found")
		return info
	}
	clusterManager := k8s.NewClusterInfoManager(clusterAddr)
	clusterKey, ok := clusterManager.ClusterKey()
	if !ok {
		logging.Get().Error().Msg("get cluster key failed")
		return info
	}
	info.ClusterKey = clusterKey

	return info
}
