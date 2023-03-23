package mozart

import (
	"github.com/go-redis/redis/v8"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo" // todo: 去掉依赖
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/security-rd/go-pkg/sdk/palace"
)

type option func(co *depOption)

type depOption struct {
	palace *palace.Palace
	cm     *k8s.ClusterInfoManager
	prInfo *nodeinfo.PodResInfo
	redis  *redis.Client
}

func SetPalace(p *palace.Palace) option {
	return func(do *depOption) {
		do.palace = p
	}
}

func SetClusterManager(cm *k8s.ClusterInfoManager) option {
	return func(do *depOption) {
		do.cm = cm
	}
}

func SetPrInfo(p *nodeinfo.PodResInfo) option {
	return func(do *depOption) {
		do.prInfo = p
	}
}

func SetRedis(r *redis.Client) option {
	return func(do *depOption) {
		do.redis = r
	}
}
