package mutation

import (
	"encoding/json"
	"os"

	"github.com/sirupsen/logrus"

	"k8s.io/api/admission/v1beta1"
	corev1 "k8s.io/api/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func mutate(review *v1beta1.AdmissionReview) *v1beta1.AdmissionResponse {
	req := review.Request

	pod := &corev1.Pod{}
	if err := json.Unmarshal(req.Object.Raw, pod); err != nil {
		logrus.Errorf("Could not unmarshal raw object: %v", err)
		return &v1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	logrus.Infof("AdmissionReview for Kind=%v, Namespace=%v Name=%v (%v) UID=%v patchOperation=%v UserInfo=%v",
		req.Kind, req.Namespace, req.Name, pod.Name, req.UID, req.Operation, req.UserInfo)

	seccompProtect := false
	seccompProfileName := ""

	for k, v := range pod.Labels {
		if k == "tensorsec.seccompprotect" {
			seccompProtect = true
			seccompProfileName = v
		}
	}

	if !seccompProtect {
		return &v1beta1.AdmissionResponse{
			Allowed: true,
		}
	}

	namespace := os.Getenv("MY_POD_NAMESPACE")

	patches := PatchPod(pod, seccompProfileName, namespace)

	patchData, err := json.Marshal(patches)
	if err != nil {
		logrus.Errorf("Could not marshal patches: %v", err)
		return &v1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	pt := v1beta1.PatchTypeJSONPatch
	return &v1beta1.AdmissionResponse{
		Allowed:   true,
		Patch:     patchData,
		PatchType: &pt,
	}
}
