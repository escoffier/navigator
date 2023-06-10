package assets

import (
	"context"
	"encoding/json"
	"fmt"
	imagesec2 "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"regexp"
	"runtime/debug"
	"sync"
	"time"

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
	initConfig      config.Config             // init config load from yaml
	nodeImageConfig imagesec2.NodeImageConfig // dynamic config synced from console
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

func (m *Manager) Type() services.ServiceType {
	return services.TypeServiceImageAsset
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

func (m *Manager) PreRun(cfg config.Config, nc imagesec2.NodeImageConfig, bs *util.BroadcastServer) error {
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
	m.subscribeChan = bs.Subscribe(string(services.TypeServiceImageAsset))

	logging.Get().Info().Msg("image asset manager pre run ok")

	return nil
}

func (m *Manager) updateNodeImageConfig(cfg imagesec2.NodeImageConfig) {
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
				if event.Type == types2.NotifyEventTypeConfigModified {
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

func (m *Manager) Run() error {
	logging.Get().Info().Msg("node image asset service starting")

	// handle notify
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
			}
		}()
		m.handleNotifyEvent()
	}()

	// get node sys info
	sysInfo := GetNodeSysInfo()
	logging.Get().Debug().Str("clusterKey", sysInfo.ClusterKey).Msg("get node sys info")

	sendFunc := func(report *imagesec.NodeReport) error {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(m.getMqTimeout())*time.Second)
		defer cancel()
		return m.SendToMq(ctx, report)
	}

	for {
		time.Sleep(time.Duration(m.getReportInterval()) * time.Second)

		// list all images
		imgs, err := m.runtime.ListImages()
		if err != nil {
			logging.Get().Err(err).Msg("failed to list images")
			continue
		}
		logging.Get().Debug().Int("imageCount", len(imgs)).Msg("found node images")

		// fetch image detail
		for _, v := range imgs {
			// filter by repo tag
			if m.shouldExcludeImage(v.RepoTags) {
				logging.Get().Info().Interface("repoTags", v.RepoTags).Msg("repo tag match report exclude rule,not reported")
				continue
			}
			// filter by digest.some image with digest curlimages/curl@sha256:5a2a25d9 while have empty repo tags.
			if m.shouldExcludeImage(v.RepoDigests) {
				logging.Get().Info().Interface("repoDigests", v.RepoDigests).Msg("digest match report exclude rule,not reported")
				continue
			}

			// fill node sys info
			report := &imagesec.NodeReport{}
			report.UUID = util.GenerateUUIDHex()
			report.NodeInfo.ClusterKey = sysInfo.ClusterKey
			report.NodeInfo.HostName = sysInfo.hostName
			report.NodeInfo.Ip = sysInfo.hostIP

			// get image base info
			detail, err := m.runtime.GetImageInspect(v.ID)
			if err != nil {
				logging.Get().Err(err).Interface("repoTags", v.RepoTags).Msg("failed to inspect image")
				continue
			}

			// get image layer
			history, err := m.runtime.ImageHistory(v.ID)
			if err != nil {
				logging.Get().Err(err).Interface("repoTags", v.RepoTags).Msg("failed to get image history")
				continue
			}

			imageMeta := transformImageInfo(detail, history)
			report.Images = append(report.Images, imageMeta)

			// report one image once a time to avoid too large kafka msg
			report.ReportedAt = time.Now().Unix()
			err = sendFunc(report)
			if err != nil {
				logging.Get().
					Err(err).
					Str("uuid", report.UUID).
					Str("imageId", imageMeta.ImageId).
					Interface("repoTags", imageMeta.RepoTags).
					Interface("digests", imageMeta.Digests).
					Msg("failed to send node image report to mq")
			} else {
				logging.Get().
					Info().
					Str("uuid", report.UUID).
					Str("imageId", imageMeta.ImageId).
					Interface("repoTags", imageMeta.RepoTags).
					Interface("digests", imageMeta.Digests).
					Msg("send node image report ok")
			}
		}

	}
}

func (m *Manager) SendToMq(ctx context.Context, report *imagesec.NodeReport) error {
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
