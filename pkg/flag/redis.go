package flag

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	redisEndpoint = "redis-endpoint"
	redisPassword = "redis-password"
)

// RedisOpts the Redis options.
type RedisOpts struct {
	Endpoint string
	Password string
	DB       int
}

// NewDefaultRedisOpts returns a new default redis options.
func NewDefaultRedisOpts() *RedisOpts {
	return &RedisOpts{
		Endpoint: "localhost:6379",
		Password: "12345",
	}
}

// GetRedisOpts parses the cobra.Command and returns the RedisOpts.
func GetRedisOpts(cmd *cobra.Command) *RedisOpts {
	return &RedisOpts{
		Endpoint: viper.GetString(redisEndpoint),
		Password: viper.GetString(redisPassword),
	}
}

func GetRedisOptsFromEnv() *RedisOpts {
	if os.Getenv("IS_MAIN_CLUSTER") == "true" {
		return &RedisOpts{
			Endpoint: os.Getenv("REDIS_CLUSTER_HOST"),
			Password: os.Getenv("REDIS_PASSWORD"),
		}
	}
	return &RedisOpts{
		Endpoint: os.Getenv("REDIS_SINGLE_HOST"),
		Password: os.Getenv("REDIS_PASSWORD"),
	}
}

// AddRedisFlags adds the Redis-specific command line arguments to the cobra.Command.
func AddRedisFlags(cmd *cobra.Command) {
	defaultOpts := NewDefaultRedisOpts()
	cmd.PersistentFlags().String(redisEndpoint, defaultOpts.Endpoint, "Redis endpoint")
	cmd.PersistentFlags().String(redisPassword, defaultOpts.Password, "Redis password")
	for _, flag := range []string{redisEndpoint, redisPassword} {
		err := viper.BindPFlag(flag, cmd.PersistentFlags().Lookup(flag))
		if err != nil {
			panic(err)
		}
	}
}
