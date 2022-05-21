package assets

import corev1 "k8s.io/api/core/v1"

// NodeIsReady 检查node是否处于ready状态
// 只有当node的`存在`Ready状态且为true，且磁盘空间压力、内存压力、进程压力、网络配置都为false时 nodes才算可用。
// https://kubernetes.io/zh/docs/concepts/architecture/nodes/#condition
func NodeIsReady(node *corev1.Node) bool {
	var isReady bool
	for _, v := range node.Status.Conditions {
		switch v.Type {
		case corev1.NodeReady:
			// 只有当存在 Ready 条件，且此条件为true时，节点才可用
			if v.Status == corev1.ConditionTrue {
				isReady = true
			} else {
				return false
			}

		default:
			// 当资源压力不为false时，即为true或者unknown时，表示节点不可用
			if v.Status != corev1.ConditionFalse {
				return false
			}
		}
	}

	return isReady
}
