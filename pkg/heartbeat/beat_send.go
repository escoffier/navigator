package heartbeat

import (
	"context"
	json "github.com/json-iterator/go"
	"github.com/segmentio/kafka-go"
	"gitlab.com/piccolo_su/vegeta/pkg/env"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
	"os"
	"runtime/debug"
	"time"
)

var startTime time.Time

type BeatSend struct {
	writer mq.Writer
	topic  string
	ticker *time.Ticker

	selfInfo *SelfInfo
}
type SelfInfo struct {
	ClusterKey    string
	NodeName      string
	Version       string
	Namespace     string
	PodName       string
	AppLabel      string
	ContainerName string
}

func NewBeatSend(writer mq.Writer, topic string, duration time.Duration, clusterKey string) *BeatSend {
	podName := os.Getenv("MY_POD_NAME")
	namespace := os.Getenv(env.SoftName)
	nodeName := os.Getenv(env.NodeName)
	appLabel := os.Getenv(env.PodAppLabel)
	version := os.Getenv(env.SoftVersionEnv)
	info := &SelfInfo{
		ClusterKey:    clusterKey,
		NodeName:      nodeName,
		Version:       version,
		Namespace:     namespace,
		PodName:       podName,
		AppLabel:      appLabel,
		ContainerName: "",
	}
	beat := BeatSend{
		writer:   writer,
		topic:    topic,
		ticker:   time.NewTicker(duration),
		selfInfo: info,
	}
	startTime = time.Now()
	return &beat
}

func (b *BeatSend) Run() {
	defer func() {
		if err := recover(); err != nil {
			logging.Get().Error().Msgf("Panic when async send heartbeat: %v. Stack: %s", err, debug.Stack())
		}
	}()
	for t := range b.ticker.C {
		logging.Get().Debug().Msg("report heartbeat")
		ctx, _ := context.WithTimeout(context.Background(), time.Second)
		marshal, err := json.Marshal(BeatMessage{
			Action: ActionTypeBeat,
			Data: DataTypeBeat{
				SelfInfo:   b.selfInfo,
				CreateTime: startTime,
				BeatTime:   t,
			},
		})
		if err != nil {
			logging.Get().Err(err).Msg("marshal DataTypeBeat failed")
		}

		err = b.writer.Write(ctx, b.topic, kafka.Message{
			Key:   []byte(b.selfInfo.ClusterKey),
			Value: marshal,
		})
		if err != nil {
			logging.Get().Err(err).Msg("send heartbeat failed")
		}
	}
}

func (s *SelfInfo) IsValid() bool {
	return s.ClusterKey != "" && s.NodeName != "" && s.Namespace != "" && s.PodName != "" && s.ContainerName != ""
}
