package service

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/sirupsen/logrus"
	util "gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/microsegmutator/util"
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/processors"
	"k8s.io/api/admission/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ Service = (*mutationService)(nil)

func (m *mutationService) MutateLabels(ctx context.Context, parameters *processors.MutatorParameters, pod *corev1.Pod) []*processors.Patch {
	patches := m.patchPod(ctx, pod, parameters.Cluster, parameters.Namespace)

	for _, patch := range patches {
		p := patch.Value.(string)
		err := util.EnsureValidK8sLabel(p)
		if err != nil {
			logrus.Errorf("Patch label %s sanity check failed: %w", patch.Value, err)
			return nil
		}
	}
	return patches
	//patchData, err := json.Marshal(patches)
	//if err != nil {
	//	logrus.Errorf("failed to marshal patch")
	//	return nil
	//}
	//return patchData
}

func (m *mutationService) MutatePodLabels(ctx context.Context, cluster string, review *v1beta1.AdmissionReview) *v1beta1.AdmissionResponse {
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

	logrus.Infof("AdmissionReview for Cluster=%s Kind=%v, Namespace=%v Name=%v (%v) UID=%v patchOperation=%v UserInfo=%v Labels=%v",
		cluster, req.Kind, req.Namespace, req.Name, pod.Name, req.UID, req.Operation, req.UserInfo, pod.Labels)

	patches := m.patchPod(ctx, pod, cluster, req.Namespace)

	for _, patch := range patches {
		p := patch.Value.(string)
		err := util.EnsureValidK8sLabel(p)
		if err != nil {
			logrus.Errorf("Patch label %s sanity check failed: %w", patch.Value, err)
			return &v1beta1.AdmissionResponse{
				Result: &metav1.Status{
					Message: err.Error(),
				},
			}
		}
	}

	if len(patches) == 0 {
		return &v1beta1.AdmissionResponse{
			Allowed: true,
		}
	}

	patchData, err := json.Marshal(patches)
	if err != nil {
		logrus.Errorf("Could not marshal patches: %v", err)
		return &v1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	logrus.Infof("AdmissionResponse patch json: %s", string(patchData))

	pt := v1beta1.PatchTypeJSONPatch
	return &v1beta1.AdmissionResponse{
		Allowed:   true,
		Patch:     patchData,
		PatchType: &pt,
	}
}

func (m *mutationService) patchPod(ctx context.Context, pod *corev1.Pod, cluster, namespace string) []*processors.Patch {
	var resID uint32
	var newResLabelValue, newSegLabelValue string
	resourcePatchOp := "add"
	segmentPatchOp := "add"
	patches := make([]*processors.Patch, 0)

	if pod.Labels == nil {
		pod.Labels = map[string]string{}
	}
	for key, _ := range pod.Labels {
		if key == util.ResourceLabelKey {
			resourcePatchOp = "replace"
		}
		if key == util.SegmentLabelKey {
			segmentPatchOp = "replace"
		}
	}

	resKind := pod.Kind
	resName := pod.Name
	owner := metav1.GetControllerOf(pod)
	if owner != nil && owner.Kind != "Node" {
		if owner.Kind == "ReplicaSet" {
			rs, _ := m.k8sCli.AppsV1().ReplicaSets(namespace).
				Get(owner.Name, metav1.GetOptions{})
			rsowner := metav1.GetControllerOf(rs)
			if rsowner != nil {
				owner = rsowner
			}
		}
		resKind = owner.Kind
		resName = owner.Name
	}

	tensorCluster, err := m.backend.GetClusterByName(ctx, cluster)
	if err != nil {
		logrus.Errorf("failed to get cluster by name: %s", cluster)
		return patches
	}
	logrus.Infof("cluster key: %s", tensorCluster.Key)
	resID = util.GenID(tensorCluster.Key, namespace, resKind, resName)
	logrus.Infof("resource info is %s:%s:%s:%s", cluster, namespace, resKind, resName)

	newResLabelValue = fmt.Sprintf("%d", resID)
	patches = append(patches, &processors.Patch{
		Op:    resourcePatchOp,
		Path:  fmt.Sprintf("/metadata/labels/%s", util.ResourceLabelKey),
		Value: newResLabelValue,
	})
	logrus.Infof("Will patch pod %s:%s with %s=%s", namespace, pod.Name, util.ResourceLabelKey, newResLabelValue)

	res, err := m.backend.GetResourceByID(ctx, resID)
	if err != nil {
		logrus.Errorf("Failed to decide segment label, will set it as %s: %w", util.SegmentInvalidName, err)
		newSegLabelValue = util.SegmentInvalidName
	}
	if res.SegmentID != 0 {
		newSegLabelValue = fmt.Sprintf("%d", res.SegmentID)
	}

	if newSegLabelValue == "" {
		logrus.Infof("Will not patch pod %s:%s with %s", namespace, pod.Name, util.SegmentLabelKey)
	} else {
		patches = append(patches, &processors.Patch{
			Op:    segmentPatchOp,
			Path:  fmt.Sprintf("/metadata/labels/%s", util.SegmentLabelKey),
			Value: newSegLabelValue,
		})
		logrus.Infof("Will patch pod %s:%s with %s=%s", namespace, pod.Name, util.SegmentLabelKey, newSegLabelValue)
	}

	return patches
}
