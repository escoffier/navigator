package mutation

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
)

// Patch represents a JSON patch to be applied
type Patch struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

const (
	envPatchTemplate = "/spec/containers/%d/env"
)

// PatchPod patches a single pod with seccomp profile annotation
func PatchPod(pod *corev1.Pod, seccompProfileName string, namespace string) []*Patch {
	patches := make([]*Patch, 0)

	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}

	newAnnotations := make(map[string]string)

	for index, element := range pod.Annotations {
		if index != "seccomp.security.alpha.kubernetes.io/pod" {
			newAnnotations[index] = element
		}
	}

	newAnnotations["seccomp.security.alpha.kubernetes.io/pod"] = fmt.Sprintf(
		"localhost/operator/%s/tensorsec-profiles/%s.json", namespace, seccompProfileName)

	patches = append(patches, &Patch{
		Op:    "replace",
		Path:  "/metadata/annotations",
		Value: newAnnotations,
	})

	// for i := range pod.Spec.Containers {
	// 	if pod.Spec.Containers[i].SecurityContext == nil {
	// 		pod.Spec.Containers[i].SecurityContext = &corev1.SecurityContext{}
	// 	}
	// 	if pod.Spec.Containers[i].SecurityContext.AllowPrivilegeEscalation == nil || !(*pod.Spec.Containers[i].SecurityContext.AllowPrivilegeEscalation) {
	// 		*pod.Spec.Containers[i].SecurityContext.AllowPrivilegeEscalation = true
	// 		patches = append(patches, &Patch{
	// 			Op:    "replace",
	// 			Path:  fmt.Sprintf("/spec/containers/%d/securityContext", i),
	// 			Value: pod.Spec.Containers[i].SecurityContext,
	// 		})
	// 	}
	// }

	return patches
}
