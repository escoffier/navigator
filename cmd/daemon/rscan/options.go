package rscan

import (
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
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
