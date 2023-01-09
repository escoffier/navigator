package service

import (
	"context"
	"encoding/json"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/microsegmutator/util"
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/processors"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/security-rd/go-pkg/logging"
	"k8s.io/api/admission/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ Service = (*mutationService)(nil)

func (m *mutationService) MutateLabels(ctx context.Context, parameters *processors.MutatorParameters, pod *corev1.Pod) ([]*processors.Patch, error) {
	patches := m.patchPod(ctx, pod, parameters.ClusterKey, parameters.Namespace)
	for _, patch := range patches {
		p := patch.Value.(map[string]string)
		for _, v := range p {
			err := util.EnsureValidK8sLabel(v)
			if err != nil {
				logging.Get().Err(err).Msgf("Patch label %s sanity check failed", patch.Value)
				return nil, nil
			}
		}
	}
	return patches, nil
}

func (m *mutationService) MutatePodLabels(ctx context.Context, cluster string, review *v1beta1.AdmissionReview) *v1beta1.AdmissionResponse {
	req := review.Request

	pod := &corev1.Pod{}
	if err := json.Unmarshal(req.Object.Raw, pod); err != nil {
		logging.Get().Err(err).Msgf("Could not unmarshal raw object")
		return &v1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	logging.Get().Info().Msgf("AdmissionReview for Cluster=%s Kind=%v, Namespace=%v Name=%v (%v) UID=%v patchOperation=%v UserInfo=%v Labels=%v",
		cluster, req.Kind, req.Namespace, req.Name, pod.Name, req.UID, req.Operation, req.UserInfo, pod.Labels)

	patches := m.patchPod(ctx, pod, cluster, req.Namespace)

	for _, patch := range patches {
		p := patch.Value.(string)
		err := util.EnsureValidK8sLabel(p)
		if err != nil {
			logging.Get().Err(err).Msgf("Patch label %s sanity check failed", patch.Value)
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
		logging.Get().Err(err).Msgf("Could not marshal patches")
		return &v1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	logging.Get().Info().Msgf("AdmissionResponse patch json: %s", string(patchData))

	pt := v1beta1.PatchTypeJSONPatch
	return &v1beta1.AdmissionResponse{
		Allowed:   true,
		Patch:     patchData,
		PatchType: &pt,
	}
}

func (m *mutationService) MutateNamespaceLabels(ctx context.Context, parameters *processors.MutatorParameters, ns *corev1.Namespace) ([]*processors.Patch, error) {
	patches := m.patchNamespace(ctx, ns, parameters.ClusterKey)

	for _, patch := range patches {
		p := patch.Value.(string)
		err := util.EnsureValidK8sLabel(p)
		if err != nil {
			logging.Get().Err(err).Msgf("Patch label %s sanity check failed", patch.Value)
			return nil, nil
		}
	}
	return patches, nil
}

func (m *mutationService) patchPod(ctx context.Context, pod *corev1.Pod, clusterKey, namespace string) []*processors.Patch {
	var resID uint32
	var newResLabelValue, newSegLabelValue string
	patchOp := "add"
	patches := make([]*processors.Patch, 0)

	values := make(map[string]string, 1)
	if len(pod.Labels) > 0 {
		patchOp = "replace"
		for k, v := range pod.Labels {
			values[k] = v
		}
	}

	resKind := pod.Kind
	resName := pod.Name
	owner := metav1.GetControllerOf(pod)
	if owner != nil && owner.Kind != "Node" {
		logging.Get().Info().Msgf("owner kind: %s", owner.Kind)
		if owner.Kind == "ReplicaSet" {
			logging.Get().Info().Msgf("owner kind: %s", owner.Kind)
			clusterManger, ok := k8s.GetClusterManager()
			if !ok {
				logging.Get().Error().Msg("get cluster manager err")
			} else {
				k8sCli, ok := clusterManger.GetClient(clusterKey)
				if !ok {
					logging.Get().Error().Msg("get k8s client err")
				} else {
					rs, err := k8sCli.Clientset.AppsV1().ReplicaSets(namespace).Get(ctx, owner.Name, metav1.GetOptions{})
					if err != nil {
						logging.Get().Err(err).Msgf("get ReplicaSets %s err", owner.Name)
					} else {
						rsOwner := metav1.GetControllerOf(rs)
						if rsOwner != nil {
							resKind = rsOwner.Kind
							resName = rsOwner.Name
						}
					}
				}
			}
		} else {
			resKind = owner.Kind
			resName = owner.Name
		}
	}

	resID = util.GenID(clusterKey, namespace, resKind, resName)
	logging.Get().Info().Msgf("resource info is %s/%s/%s/%s", clusterKey, namespace, resKind, resName)

	newResLabelValue = fmt.Sprintf("%d", resID)

	values[util.ResourceLabelKey] = newResLabelValue
	logging.Get().Info().Msgf("Will patch pod %s:%s with %s=%s", namespace, pod.Name, util.ResourceLabelKey, newResLabelValue)

	res, err := m.backend.GetResourceByID(ctx, resID)
	if err != nil {
		logging.Get().Err(err).Msgf("Failed to decide segment label, will set it as %s", util.SegmentInvalidName)
		newSegLabelValue = util.SegmentInvalidName
	}
	if res.SegmentID != 0 {
		newSegLabelValue = fmt.Sprintf("%d", res.SegmentID)
	}

	if newSegLabelValue == "" {
		logging.Get().Info().Msgf("Will not patch pod %s:%s with %s", namespace, pod.Name, util.SegmentLabelKey)
	} else {
		values[util.SegmentLabelKey] = newSegLabelValue
		logging.Get().Info().Msgf("Will patch pod %s:%s with %s=%s", namespace, pod.Name, util.SegmentLabelKey, newSegLabelValue)
	}

	patches = append(patches, &processors.Patch{
		Op:    patchOp,
		Path:  "/metadata/labels",
		Value: values,
	})
	return patches
}

func (m *mutationService) patchNamespace(ctx context.Context, ns *corev1.Namespace, clusterKey string) []*processors.Patch {
	var nsID uint32
	var newNsLabelValue string
	nsPatchOp := "add"

	patches := make([]*processors.Patch, 0)

	if ns.Labels == nil {
		ns.Labels = map[string]string{}
	}
	for key := range ns.Labels {
		if key == util.NamespaceLabelKey {
			nsPatchOp = "replace"
		}
	}

	nsID = util.GenID(clusterKey, ns.Name)
	logging.Get().Info().Msgf("namespace info is %s:%s", clusterKey, ns.Name)

	newNsLabelValue = fmt.Sprintf("%d", nsID)
	patches = append(patches, &processors.Patch{
		Op:    nsPatchOp,
		Path:  fmt.Sprintf("/metadata/labels/%s", util.NamespaceLabelKey),
		Value: newNsLabelValue,
	})

	logging.Get().Info().Msgf("Will patch namespace %s with %s=%s", ns.Name, util.NamespaceLabelKey, newNsLabelValue)

	return patches
}
