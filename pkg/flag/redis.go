package flag

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	redisEndpoint = "redis-endpoint"
)

// RedisOpts the Redis options.
type RedisOpts struct {
	Endpoint string
}

// NewDefaultRedisOpts returns a new default redis options.
func NewDefaultRedisOpts() *RedisOpts {
	return &RedisOpts{
		Endpoint: "localhost:6379",
	}
}

// GetRedisOpts parses the cobra.Command and returns the RedisOpts.
func GetRedisOpts(cmd *cobra.Command) *RedisOpts {
	return &RedisOpts{
		Endpoint: viper.GetString(redisEndpoint),
	}
}

// AddRedisFlags adds the Redis-specific command line arguments to the cobra.Command.
func AddRedisFlags(cmd *cobra.Command) {
	defaultOpts := NewDefaultRedisOpts()
	cmd.PersistentFlags().String(redisEndpoint, defaultOpts.Endpoint, "Redis endpoint")
	for _, flag := range []string{redisEndpoint} {
		err := viper.BindPFlag(flag, cmd.PersistentFlags().Lookup(flag))
		if err != nil {
			panic(err)
		}
	}
}
