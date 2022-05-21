package assets

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

func TestNodeIsReady(t *testing.T) {
	var cases = []struct {
		node  *corev1.Node
		ready bool
	}{
		{
			node: &corev1.Node{
				// Conditions 为空
				Status: corev1.NodeStatus{
					Conditions: []corev1.NodeCondition{},
				},
			},
			ready: false,
		},

		{
			node: &corev1.Node{
				Status: corev1.NodeStatus{
					// 虽然为ready，但是有内存压力
					Conditions: []corev1.NodeCondition{
						{
							Type:   corev1.NodeReady,
							Status: corev1.ConditionTrue,
						},

						{
							Type:   corev1.NodeMemoryPressure,
							Status: corev1.ConditionTrue,
						},

						{
							Type:   corev1.NodePIDPressure,
							Status: corev1.ConditionFalse,
						},

						{
							Type:   corev1.NodeDiskPressure,
							Status: corev1.ConditionFalse,
						},

						{
							Type:   corev1.NodeNetworkUnavailable,
							Status: corev1.ConditionFalse,
						},
					},
				},
			},
			ready: false,
		},

		{
			node: &corev1.Node{
				Status: corev1.NodeStatus{
					// 虽然为ready，但是有PID压力
					Conditions: []corev1.NodeCondition{
						{
							Type:   corev1.NodeReady,
							Status: corev1.ConditionTrue,
						},

						{
							Type:   corev1.NodeMemoryPressure,
							Status: corev1.ConditionFalse,
						},

						{
							Type:   corev1.NodePIDPressure,
							Status: corev1.ConditionTrue,
						},

						{
							Type:   corev1.NodeDiskPressure,
							Status: corev1.ConditionFalse,
						},

						{
							Type:   corev1.NodeNetworkUnavailable,
							Status: corev1.ConditionFalse,
						},
					},
				},
			},
			ready: false,
		},

		{
			node: &corev1.Node{
				Status: corev1.NodeStatus{
					// 虽然为ready，但是有磁盘压力
					Conditions: []corev1.NodeCondition{
						{
							Type:   corev1.NodeReady,
							Status: corev1.ConditionTrue,
						},

						{
							Type:   corev1.NodeMemoryPressure,
							Status: corev1.ConditionFalse,
						},

						{
							Type:   corev1.NodePIDPressure,
							Status: corev1.ConditionFalse,
						},

						{
							Type:   corev1.NodeDiskPressure,
							Status: corev1.ConditionTrue,
						},

						{
							Type:   corev1.NodeNetworkUnavailable,
							Status: corev1.ConditionFalse,
						},
					},
				},
			},
			ready: false,
		},

		{
			node: &corev1.Node{
				Status: corev1.NodeStatus{
					// ready为unknown
					Conditions: []corev1.NodeCondition{
						{
							Type:   corev1.NodeReady,
							Status: corev1.ConditionUnknown,
						},

						{
							Type:   corev1.NodeMemoryPressure,
							Status: corev1.ConditionFalse,
						},

						{
							Type:   corev1.NodePIDPressure,
							Status: corev1.ConditionFalse,
						},

						{
							Type:   corev1.NodeDiskPressure,
							Status: corev1.ConditionFalse,
						},

						{
							Type:   corev1.NodeNetworkUnavailable,
							Status: corev1.ConditionFalse,
						},
					},
				},
			},
			ready: false,
		},

		{
			node: &corev1.Node{
				Status: corev1.NodeStatus{
					Conditions: []corev1.NodeCondition{
						{
							Type:   corev1.NodeReady,
							Status: corev1.ConditionTrue,
						},

						{
							Type:   corev1.NodeMemoryPressure,
							Status: corev1.ConditionUnknown,
						},

						{
							Type:   corev1.NodePIDPressure,
							Status: corev1.ConditionFalse,
						},

						{
							Type:   corev1.NodeDiskPressure,
							Status: corev1.ConditionFalse,
						},

						{
							Type:   corev1.NodeNetworkUnavailable,
							Status: corev1.ConditionFalse,
						},
					},
				},
			},
			ready: false,
		},

		{
			node: &corev1.Node{
				Status: corev1.NodeStatus{
					Conditions: []corev1.NodeCondition{
						{
							Type:   corev1.NodeReady,
							Status: corev1.ConditionTrue,
						},

						{
							Type:   corev1.NodeMemoryPressure,
							Status: corev1.ConditionUnknown,
						},

						{
							Type:   corev1.NodePIDPressure,
							Status: corev1.ConditionUnknown,
						},

						{
							Type:   corev1.NodeDiskPressure,
							Status: corev1.ConditionFalse,
						},

						{
							Type:   corev1.NodeNetworkUnavailable,
							Status: corev1.ConditionFalse,
						},
					},
				},
			},
			ready: false,
		},

		{
			node: &corev1.Node{
				Status: corev1.NodeStatus{
					Conditions: []corev1.NodeCondition{
						{
							Type:   corev1.NodeReady,
							Status: corev1.ConditionUnknown,
						},

						{
							Type:   corev1.NodeMemoryPressure,
							Status: corev1.ConditionUnknown,
						},

						{
							Type:   corev1.NodePIDPressure,
							Status: corev1.ConditionUnknown,
						},

						{
							Type:   corev1.NodeDiskPressure,
							Status: corev1.ConditionTrue,
						},

						{
							Type:   corev1.NodeNetworkUnavailable,
							Status: corev1.ConditionTrue,
						},
					},
				},
			},
			ready: false,
		},

		{
			node: &corev1.Node{
				Status: corev1.NodeStatus{
					Conditions: []corev1.NodeCondition{
						{
							Type:   corev1.NodeReady,
							Status: corev1.ConditionUnknown,
						},

						{
							Type:   corev1.NodeMemoryPressure,
							Status: corev1.ConditionFalse,
						},

						{
							Type:   corev1.NodePIDPressure,
							Status: corev1.ConditionFalse,
						},

						{
							Type:   corev1.NodeDiskPressure,
							Status: corev1.ConditionFalse,
						},

						{
							Type:   corev1.NodeNetworkUnavailable,
							Status: corev1.ConditionUnknown,
						},
					},
				},
			},
			ready: false,
		},
	}

	for i, v := range cases {
		assert.Equalf(t, v.ready, NodeIsReady(v.node), "test%d", i)
	}
}
