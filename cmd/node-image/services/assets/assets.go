package assets

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"runtime/debug"
	"sync"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/node-image/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/services/helper"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"

	"github.com/docker/docker/api/types"
	dockerImage "github.com/docker/docker/api/types/image"
	"github.com/segmentio/kafka-go"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/container"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/config"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/services"
	types2 "gitlab.com/piccolo_su/vegeta/cmd/node-image/services/types"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

const (
	defaultReportInterval = 600
)

type Manager struct {
	sync.RWMutex
	runtime         container.Runtime
	err             error
	mqWriter        mq.Writer
	initConfig      config.Config                 // init config load from yaml
	nodeImageConfig imagesecModel.NodeImageConfig // dynamic config synced from console
	subscribeChan   <-chan interface{}
}

func init() {
	err := services.RegisterService(&Manager{})
	if err != nil {
		logging.Get().Err(err).Msg("failed to register image asset manager service")
	} else {
		logging.Get().Info().Msg("register image asset manager service ok")
	}
}

func (m *Manager) Type() consts.ServiceType {
	return consts.TypeServiceImageAsset
}

func (m *Manager) getMqTimeout() int64 {
	m.Lock()
	defer m.Unlock()
	return m.initConfig.ReportConfig.MqTimeout
}

func (m *Manager) getReportInterval() int64 {
	m.Lock()
	defer m.Unlock()
	if m.nodeImageConfig.SyncInterval <= 0 {
		return defaultReportInterval
	}
	return m.nodeImageConfig.SyncInterval * 60
}

func (m *Manager) PreRun(cfg config.Config, nc imagesecModel.NodeImageConfig, bs *util.BroadcastServer) error {
	// copy config
	m.initConfig = cfg
	m.nodeImageConfig = nc

	// create runtime cli
	r, err := container.CreateRuntimeCli()
	if err != nil {
		m.err = err
		logging.Get().Err(err).Msg("failed to create runtime cli")
		return err
	}
	m.runtime = r

	// create msg que cli
	mqWriter, err := mq.GetClientFactory().Writer(context.Background())
	if err != nil {
		m.err = err
		logging.Get().Err(err).Msg("failed to create mq writer")
		return err
	}
	m.mqWriter = mqWriter

	// subscribe notify
	m.subscribeChan = bs.Subscribe(string(consts.TypeServiceImageAsset))

	logging.Get().Info().Msg("image asset manager pre run ok")

	return nil
}

func (m *Manager) updateNodeImageConfig(cfg imagesecModel.NodeImageConfig) {
	m.Lock()
	defer m.Unlock()
	m.nodeImageConfig = cfg
}

func (m *Manager) handleNotifyEvent() {
	for {
		select {
		case item := <-m.subscribeChan:
			switch typed := item.(type) {
			case types2.NotifyEvent:
				event := item.(types2.NotifyEvent)
				if event.Type == consts.NotifyEventTypeConfigModified {
					logging.Get().Debug().Interface("event", event).Msg("recv config modified event,copy")

					// copy node image config
					m.updateNodeImageConfig(event.NodeImageConfig)
					continue
				}
				logging.Get().Debug().Interface("event", event).Msg("image asset ignore irrelevant event")
			default:
				logging.Get().Error().Msgf("subscribe msg type err.%v", typed)
			}
		}
	}
}

func (m *Manager) shouldExcludeImage(imageName []string) bool {
	for _, n := range imageName {
		// filter by regexp
		for _, v := range m.initConfig.ReportConfig.ExcludeImage {
			reg, err := regexp.Compile(v)
			if err != nil {
				logging.Get().Err(err).Msg("invalid report exclude image rule,please check config file")
				continue
			}
			match := reg.FindString(n)
			if len(match) > 0 {
				return true
			}
		}
	}
	return false
}

func (m *Manager) filterImage(images []types.ImageSummary) []types.ImageSummary {
	ans := make([]types.ImageSummary, 0)
	for i := range images {
		image := images[i]
		if m.shouldExcludeImage(image.RepoTags) {
			logging.Get().Info().Interface("repoTags", image.RepoTags).Msg("repo tag match report exclude rule,not reported")
			continue
		}
		// filter by digest.some image with digest curlimages/curl@sha256:5a2a25d9 while have empty repo tags.
		if m.shouldExcludeImage(image.RepoDigests) {
			logging.Get().Info().Interface("repoDigests", image.RepoDigests).Msg("digest match report exclude rule,not reported")
			continue
		}
		ans = append(ans, image)
	}
	return ans
}

func (m *Manager) SendAsset(ctx context.Context) {

	sysInfo := GetNodeSysInfo()
	logging.Get().Debug().Str("clusterKey", sysInfo.ClusterKey).Msg("get node sys info")

	ticker := time.NewTicker(time.Duration(m.getReportInterval()) * time.Second)
	defer ticker.Stop()
	batchSize := int(m.initConfig.ReportConfig.BatchSize)
	for {
		images, err := m.runtime.ListImages()
		if err != nil {
			logging.Get().Err(err).Msg("failed to list images")
			continue
		}
		logging.Get().Debug().Int("imageCount", len(images)).Msg("found node images")
		images = m.filterImage(images)
		logging.Get().Debug().Int("imageCount", len(images)).Msg("found node images and filter image")

		versionReport := imagesec.ReportDBVersion{AviraDBVersion: helper.GetAviraDBVersion().WorkVersion.Version}

		for i := 0; i < len(images); i = i + batchSize {
			batch := images[i:util.MinInt(i+batchSize, len(images))]
			if err := m.sendAssetHelp(context.Background(), batch, sysInfo, versionReport); err != nil {
				logging.Get().Err(err).Msg("send image to kafka")
				continue
			}
			logging.Get().Info().Msg("send image to kafka succeed")
		}

		ticker.Reset(time.Duration(m.getReportInterval()) * time.Second)
		<-ticker.C
	}
}

func (m *Manager) sendAssetHelp(ctx context.Context, images []types.ImageSummary, sysInfo *SysInfo, versionReport imagesec.ReportDBVersion) error {
	report := &imagesec.NodeReport{
		UUID: util.GenerateUUIDHex(),
		NodeInfo: imagesec.NodeInfo{
			ClusterKey: sysInfo.ClusterKey,
			Ip:         sysInfo.HostIP,
			HostName:   sysInfo.HostName,
		},
		Images:          make([]imagesec.ImageMeta, 0),
		ReportedAt:      time.Now().UnixMilli(),
		ReportDBVersion: versionReport,
	}

	for i := range images {
		image := images[i]
		// get image base info
		detail, err := m.runtime.GetImageInspect(image.ID)
		if err != nil {
			logging.Get().Err(err).Interface("repoTags", image.RepoTags).Msg("failed to inspect image")
			return err
		}

		// get image layer
		history, err := m.runtime.ImageHistory(image.ID)
		if err != nil {
			logging.Get().Err(err).Interface("repoTags", image.RepoTags).Msg("failed to get image history")
			return err
		}

		imageMeta := transformImageInfo(detail, history)
		report.Images = append(report.Images, imageMeta)

		logging.Get().
			Info().
			Str("uuid", report.UUID).
			Str("imageId", imageMeta.ImageId).
			Interface("repoTags", imageMeta.RepoTags).
			Interface("digests", imageMeta.Digests).Msg("node image send image")
	}

	err := m.SendToMq(ctx, report)
	return err
}

func (m *Manager) Run() error {
	logging.Get().Info().Msg("node image asset service starting")

	// handle notify
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("handleNotifyEvent panic: %v. Stack: %s", r, debug.Stack())
			}
		}()
		m.handleNotifyEvent()
	}()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("SendImage panic: %v. Stack: %s", r, debug.Stack())
			}
		}()
		m.SendAsset(context.Background())
	}()

	return nil
}

func (m *Manager) SendToMq(ctx context.Context, report *imagesec.NodeReport) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(m.getMqTimeout())*time.Second)
	defer cancel()
	msg, err := json.Marshal(report)
	if err != nil {
		return err
	}
	key := fmt.Sprintf("%s/node-report", report.NodeInfo.ClusterKey)
	err = m.mqWriter.Write(ctx, model.NodeImageTopic, kafka.Message{
		Key:   []byte(key),
		Value: msg,
	})
	if err != nil {
		return err
	}
	return nil
}

func transformImageInfo(detail types.ImageInspect, history []dockerImage.HistoryResponseItem) imagesec.ImageMeta {
	meta := imagesec.ImageMeta{
		ImageId:  detail.ID,
		RepoTags: detail.RepoTags,
		Digests:  detail.RepoDigests,
		Size:     detail.Size,
		Created:  detail.Created,
	}
	if detail.Config != nil {
		meta.ENVS = detail.Config.Env
		meta.User = detail.Config.User
	} else {
		logging.Get().Info().Interface("image", detail).Msg("transformImageInfo config is nil")
	}

	for _, v := range history {
		l := imagesec.Layer{
			Comment:   v.Comment,
			Created:   v.Created,
			CreatedBy: v.CreatedBy,
			Digest:    v.ID,
			Size:      v.Size,
		}
		meta.Layers = append(meta.Layers, l)
	}
	return meta
}
