package cis

import (
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
)

type OptionFunc func(cController *CisController)

func WithPodResInfo(p *nodeinfo.PodResInfo) OptionFunc {
	return func(cController *CisController) {
		cController.pri = p
	}
}

func WithNodePodResInfo(n *nodeinfo.NodePodsWatcher) OptionFunc {
	return func(cController *CisController) {
		cController.npw = n
	}
}

func WithClusterInfoManager(c *k8s.ClusterInfoManager) OptionFunc {
	return func(cController *CisController) {
		cController.cim = c
	}
}
