package main

import (
	"os"

	"gitlab.com/security-rd/go-pkg/logging"
	"gopkg.in/yaml.v2"
)

const (
	associatedSubject     = "ivan_podcontainer_events"
	defaultGroupID        = "ivan_holmes_palace"
	EnvECenterConcurrency = "ECENTER_CONCURRENCY"
	EnvKafkaGroupConfig   = "KAFKA_CONSUMER_GROUP_IDS"
)

var (
	groupIDConfig GroupConfig = make(map[string]string) // immutable
)

type GroupConfig map[string]string

func init() {
	v := os.Getenv(EnvKafkaGroupConfig)
	if len(v) == 0 {
		return
	}
	err := yaml.Unmarshal([]byte(v), &groupIDConfig)
	if err != nil {
		logging.Get().Err(err).Str("env", EnvKafkaGroupConfig).Msg("env parse error")
		return
	}
}

func getGroupIDOfTopic(topic string) string {
	if gid, exist := groupIDConfig[topic]; exist && len(gid) > 0 {
		return gid
	}
	return defaultGroupID
}
