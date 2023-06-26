package microseg

import (
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func Test_podsUnion(t *testing.T) {
	type args struct {
		p1s []*corev1.Pod
		p2s []*corev1.Pod
	}
	tests := []struct {
		name string
		args args
		want []*corev1.Pod
	}{
		{
			name: "",
			args: args{
				p1s: []*corev1.Pod{
					{
						ObjectMeta: v1.ObjectMeta{Namespace: "ns-1", Name: "name-1"},
					},
					{
						ObjectMeta: v1.ObjectMeta{Namespace: "ns-1", Name: "name-2"},
					},
				},
				p2s: []*corev1.Pod{
					{
						ObjectMeta: v1.ObjectMeta{Namespace: "ns-1", Name: "name-1"},
					},
					{
						ObjectMeta: v1.ObjectMeta{Namespace: "ns-2", Name: "name-3"},
					},
				},
			},
			want: []*corev1.Pod{
				{
					ObjectMeta: v1.ObjectMeta{Namespace: "ns-1", Name: "name-1"},
				},
				{
					ObjectMeta: v1.ObjectMeta{Namespace: "ns-1", Name: "name-2"},
				},
				{
					ObjectMeta: v1.ObjectMeta{Namespace: "ns-2", Name: "name-3"},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := podsUnion(tt.args.p1s, tt.args.p2s); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("podsUnion() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_dedupPods(t *testing.T) {
	type args struct {
		ps []*corev1.Pod
	}

	p1 := &corev1.Pod{
		ObjectMeta: v1.ObjectMeta{
			Namespace: "default",
			Name:      "h-11ddd",
			Labels: map[string]string{
				"app":     "httpbin",
				"version": "v1.1",
			},
		},
	}
	p2 := &corev1.Pod{
		ObjectMeta: v1.ObjectMeta{
			Namespace: "default",
			Name:      "h-xxdff",
			Labels: map[string]string{
				"app":     "httpbin",
				"version": "v1.1",
			},
		},
	}
	p3 := &corev1.Pod{
		ObjectMeta: v1.ObjectMeta{
			Namespace: "ns-1",
			Name:      "abc",
			Labels: map[string]string{
				"app":     "httpbin",
				"version": "v2.1",
			},
		},
	}
	tests := []struct {
		name string
		args args
		want []*corev1.Pod
	}{

		{
			name: "test-1",
			args: args{
				ps: []*corev1.Pod{p1, p2, p3},
			},
			want: []*corev1.Pod{p1, p3},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := dedupPods(tt.args.ps); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("dedupPods() = %v, want %v", got, tt.want)
			}
		})
	}
}
