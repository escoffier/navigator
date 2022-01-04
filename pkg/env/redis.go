package env

import "gitlab.com/piccolo_su/vegeta/pkg/util"

const (
	RedisEndpoint = "REDIS_CLUSTER_URL"
	DefaultRedisEndpoint = "redis-0:26379,redis-1:26379,redis-2:26379"

	RedisPassword = "REDIS_PASSWORD"
)

func GetRedisEndpoint() string {
	return util.GetEnvWithDefault(RedisEndpoint, DefaultRedisEndpoint)
}

func GetRedisPassword() string {
	return util.GetEnvWithDefault(RedisPassword, "")
}
