package main

import (
	"os"

	"github.com/segmentio/kafka-go"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
	"gopkg.in/yaml.v2"
)

const envKafkaTopicConfigs = "KAFKA_TOPIC_CONFIGS"

func kafkaInit() error {
	topicConfigsStr := os.Getenv(envKafkaTopicConfigs)
	var topicConfigs []kafka.TopicConfig

	err := yaml.Unmarshal([]byte(topicConfigsStr), &topicConfigs)
	if err != nil {
		logging.Get().Err(err).Str("config", topicConfigsStr).Msg("yaml unmarshal err")
		return err
	}
	if len(topicConfigs) > 0 {
		err = mq.CreateTopics(topicConfigs)
		if err != nil {
			logging.Get().Err(err).Str("create topics", topicConfigsStr).Msg("create topics err")
			return err
		}
	}
	return nil
}
func main() {
	mqType := os.Getenv(mq.EnvMQType)
	switch mqType {
	case string(mq.MQTypeKafka):
		if err := kafkaInit(); err != nil {
			logging.Get().Err(err).Msg("Kafka init error. exit badly")
			os.Exit(1)
		}
	default:
		return
	}

}
