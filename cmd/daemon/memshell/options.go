package memshell

import (
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
)

type OptionFunc func(ms *MemShell)

func WithPodResInfo(p *nodeinfo.PodResInfo) OptionFunc {
	return func(m *MemShell) {
		m.pri = p
	}
}

func WithNodePodResInfo(n *nodeinfo.NodePodsWatcher) OptionFunc {
	return func(m *MemShell) {
		m.npw = n
	}
}

func WithClusterInfoManager(c *k8s.ClusterInfoManager) OptionFunc {
	return func(m *MemShell) {
		m.cim = c
	}
}
