package rscan

import (
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/security-rd/go-pkg/logging"
	"os"
	"strconv"
)

const (
	DefaultMaxUserWatches    = 1249830
	DefaultConcurrentScanNum = 10
)

type OptionFunc func(rs *RuntimeScanner)

func WithPodResInfo(p *nodeinfo.PodResInfo) OptionFunc {
	return func(rs *RuntimeScanner) {
		rs.pri = p
	}
}

func WithNodePodResInfo(n *nodeinfo.NodePodsWatcher) OptionFunc {
	return func(rs *RuntimeScanner) {
		rs.npw = n
	}
}

func WithClusterInfoManager(c *k8s.ClusterInfoManager) OptionFunc {
	return func(rs *RuntimeScanner) {
		rs.cim = c
	}
}

func WithMaxUserWatches(maxUserWatches int64) OptionFunc {
	return func(rs *RuntimeScanner) {
		value := os.Getenv("MAX_USER_WATCHES")
		if len(value) == 0 {
			logging.Get().Debug().Int64("maxWatches", maxUserWatches).Msg("not found env,set max watches to param value")
			rs.maxUserWatches = maxUserWatches
		} else {
			watchNum, err := strconv.Atoi(value)
			if err != nil {
				logging.Get().Err(err).Int64("maxWatches", maxUserWatches).Msg("change max user watches env to param value")
				rs.maxUserWatches = maxUserWatches
			} else {
				logging.Get().Debug().Int64("maxWatches", maxUserWatches).Msg("set max watches to env")
				rs.maxUserWatches = int64(watchNum)
			}
		}
	}
}

func WithConcurrentScanNum(num int64) OptionFunc {
	return func(rs *RuntimeScanner) {
		value := os.Getenv("RSCAN_CONCURRENT_SCAN_NUM")
		if len(value) == 0 {
			rs.concurrentScanNum = num
		} else {
			tmpNum, err := strconv.Atoi(value)
			if err != nil {
				rs.concurrentScanNum = num
			} else {
				rs.concurrentScanNum = int64(tmpNum)
			}
		}
	}
}
