package scanTrivy

import (
	"github.com/go-redis/redis/v8"
)

type Option func(o *TrivySrv)

func WithRedisCli(cli *redis.Client) Option {
	return func(o *TrivySrv) {
		o.RedisCli = cli
	}
}

func WithCachePath(ca string) Option {
	return func(o *TrivySrv) {
		o.CachePath = ca
	}
}

func WithVulnRootPath(ca string) Option {
	return func(o *TrivySrv) {
		o.VulnRootPath = ca
	}
}

func WithImageCacheURL(ca string) Option {
	return func(o *TrivySrv) {
		o.ImageCacheURL = ca
	}
}

func WithPvcPath(ca string) Option {
	return func(o *TrivySrv) {
		o.PvcPath = ca
	}
}

const (
	CustomDB = "custom.db"
)
