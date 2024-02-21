package learn

import (
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/security-rd/go-pkg/mq"
)

type OptionFunc func(l *Learn)

func WithClusterMgr() OptionFunc {
	return func(l *Learn) {
	}
}

func WithPodResInfo(p *nodeinfo.PodResInfo) OptionFunc {
	return func(l *Learn) {
		l.pri = p
	}
}

func WithNodePodResInfo(n *nodeinfo.NodePodsWatcher) OptionFunc {
	return func(l *Learn) {
		l.npw = n
	}
}

func WithClusterInfoManager(c *k8s.ClusterInfoManager) OptionFunc {
	return func(l *Learn) {
		l.cim = c
	}
}

func WithMq(mq mq.Writer) OptionFunc {
	return func(l *Learn) {
		l.mq = mq
	}
}
