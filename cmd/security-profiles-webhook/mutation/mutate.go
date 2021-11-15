package mutation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	dp "github.com/novln/docker-parser"
	"github.com/sirupsen/logrus"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"k8s.io/api/admission/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/api/settings/v1alpha1"
	"k8s.io/client-go/kubernetes"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type profile struct {
	name string
	mode model.SecurityMode
}

func getResources(ctx context.Context, clientset *kubernetes.Clientset, name string, namespace string, pod *corev1.Pod) ([]model.SecurityPolicyResource, error) {
	kind := string(model.KubernetesResourcePod)
	owner := metav1.GetControllerOf(pod)
	if owner != nil {
		name = strings.ToLower(owner.Name)
		kind = strings.ToLower(owner.Kind)
		if kind == string(model.KubernetesResourceReplicaSet) {
			replicaset, err := clientset.AppsV1().ReplicaSets(namespace).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return nil, err
			}
			owner = metav1.GetControllerOf(replicaset)
			if owner != nil {
				name = strings.ToLower(owner.Name)
				kind = strings.ToLower(owner.Kind)
			}
		}
	}
	resources := make([]model.SecurityPolicyResource, len(pod.Spec.Containers)+len(pod.Spec.InitContainers))
	containerResourcesIndex := 0
	for _, container := range pod.Spec.Containers {
		reference, err := dp.Parse(container.Image)
		if err != nil {
			return nil, err
		}

		resources[containerResourcesIndex] = model.SecurityPolicyResource{
			Cluster:       "default",
			Kind:          model.KubernetesResource(kind),
			Name:          name,
			Namespace:     namespace,
			ContainerName: container.Name,
			ImageRegistry: reference.Registry(),
			ImageName:     reference.ShortName(),
			ImageTag:      reference.Tag(),
		}
		containerResourcesIndex++
	}
	for _, container := range pod.Spec.InitContainers {
		reference, err := dp.Parse(container.Image)
		if err != nil {
			return nil, err
		}

		resources[containerResourcesIndex] = model.SecurityPolicyResource{
			Cluster:       "default",
			Kind:          model.KubernetesResource(kind),
			Name:          name,
			Namespace:     namespace,
			ContainerName: container.Name,
			ImageRegistry: reference.Registry(),
			ImageName:     reference.ShortName(),
			ImageTag:      reference.Tag(),
		}
		containerResourcesIndex++
	}
	return resources, nil
}

func mutate(ctx context.Context, spec *v1alpha1.PodPresetSpec, clientset *kubernetes.Clientset, db *rdbtools.GormWrapper, review *v1beta1.AdmissionReview) *v1beta1.AdmissionResponse {
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

	resources, err := getResources(ctx, clientset, req.Name, req.Namespace, pod)
	if err != nil {
		logrus.Errorf("Failed to get resources: %v", err)
		return &v1beta1.AdmissionResponse{
			Allowed: true,
		}
	}

	dbctx, dbcancel := context.WithTimeout(ctx, 10*time.Second)
	defer dbcancel()
	profileMap := make(map[model.SecurityKind]map[string]profile)
	for _, kind := range []model.SecurityKind{model.SecurityKindApparmor, model.SecurityKindCommandWhitelist, model.SecurityKindSeccomp, model.SecurityKindDrift} {
		profileMap[kind] = make(map[string]profile)
	}
	for _, secPolicyResource := range resources {
		var secResource model.SecurityPolicyResource
		result := db.Get().WithContext(dbctx).
			Where("cluster = 'default' AND kind = ? AND name = ? AND namespace = ? AND container_name = ?", secPolicyResource.Kind, secPolicyResource.Name, secPolicyResource.Namespace, secPolicyResource.ContainerName).
			First(&secResource)
		if result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				logrus.Errorf("No such resource defined in DB: %v", result.Error)
			} else {
				logrus.Errorf("Failed to get resource from DB: %v", result.Error)
			}
			continue
		}

		var p model.SecurityPolicy
		if secResource.SecurityPolicyID == nil {
			logrus.Infof("Pod %v: no policy attached to resource %v", pod.Name, secResource)
			continue
		}
		result = db.Get().WithContext(dbctx).Preload(clause.Associations).First(&p, *secResource.SecurityPolicyID)
		if result.Error != nil {
			logrus.Errorf("Failed to get policy from DB: %v", result.Error)
			continue
		}

		if !p.Active {
			logrus.Infof("Pod %v: policy for %v not active", pod.Name, secResource)
			continue
		}

		if p.ApparmorProfile.Enabled {
			profileName := fmt.Sprintf("%s-%d", model.SecurityKindApparmor, p.ID)
			profileMap[model.SecurityKindApparmor][secPolicyResource.ContainerName] = profile{
				name: profileName,
				mode: p.Mode,
			}
		}
		if p.SeccompProfile.Enabled {
			profileName := fmt.Sprintf("%s-%d", model.SecurityKindSeccomp, p.ID)
			profileMap[model.SecurityKindSeccomp][secPolicyResource.ContainerName] = profile{
				name: profileName,
				mode: p.Mode,
			}
		}
		if p.CommandWhitelistProfile.Enabled {
			profileName := fmt.Sprintf("%s-%d", model.SecurityKindCommandWhitelist, p.ID)
			profileMap[model.SecurityKindCommandWhitelist][secPolicyResource.ContainerName] = profile{
				name: profileName,
				mode: p.Mode,
			}
		}
		if p.DriftProfile.Enabled {
			profileName := fmt.Sprintf("%s-%d", model.SecurityKindDrift, p.ID)
			profileMap[model.SecurityKindDrift][secPolicyResource.ContainerName] = profile{
				name: profileName,
				mode: p.Mode,
			}
		}
	}

	logrus.Infof("AdmissionReview for Kind=%v, Namespace=%v Name=%v (%v) UID=%v patchOperation=%v UserInfo=%v",
		req.Kind, req.Namespace, req.Name, pod.Name, req.UID, req.Operation, req.UserInfo)

	if len(profileMap[model.SecurityKindApparmor]) == 0 && len(profileMap[model.SecurityKindCommandWhitelist]) == 0 && len(profileMap[model.SecurityKindSeccomp]) == 0 && len(profileMap[model.SecurityKindDrift]) == 0 {
		logrus.Infof("Pod %v: nothing to apply", pod.Name)
		return &v1beta1.AdmissionResponse{
			Allowed: true,
		}
	}

	patches := make([]*Patch, 0)

	annotationKeys := make([]string, 0)
	annotationValues := make([]string, 0)

	for container, profile := range profileMap[model.SecurityKindSeccomp] {
		logrus.Infof("Applying seccomp profile %v to container %v", profile.name, container)
		// securityContextPatch := PatchSecurityContext(pod, container, fmt.Sprintf("tensorsec/%s", profile.name))
		securityContextPatch := PatchSecurityContext(pod, container, fmt.Sprintf("%s", profile.name))
		preVersionFlag := os.Getenv("PRE119")

		if securityContextPatch != nil {
			if preVersionFlag == "" || preVersionFlag != "true" {
				patches = append(patches, securityContextPatch)
			} else {
				seccompAnnotionKey := fmt.Sprintf("seccomp.security.alpha.kubernetes.io/pod")
				seccompAnnotionValue := fmt.Sprintf("localhsot/%s", profile.name)
				annotationKeys = append(annotationKeys, seccompAnnotionKey)
				annotationValues = append(annotationValues, seccompAnnotionValue)
			}

		}
		seccompAnnotationKey := fmt.Sprintf("container.seccomp.security.alpha.kubernetes.io/%s", container)
		// seccompAnnotationValue := fmt.Sprintf("localhost/tensorsec/%s", profile.name)
		seccompAnnotationValue := fmt.Sprintf("localhost/%s", profile.name)
		// annotationKeys = append(annotationKeys, seccompAnnotationKey)
		// annotationValues = append(annotationValues, seccompAnnotationValue)
		logrus.Infof("%v %v", seccompAnnotationKey, seccompAnnotationValue)
	}

	for container, profile := range profileMap[model.SecurityKindApparmor] {
		logrus.Infof("Applying apparmor profile %v to container %v", profile.name, container)
		appArmorAnnotationKey := fmt.Sprintf("container.apparmor.security.beta.kubernetes.io/%s", container)
		appArmorAnnotationValue := fmt.Sprintf("localhost/%s", profile.name)
		annotationKeys = append(annotationKeys, appArmorAnnotationKey)
		annotationValues = append(annotationValues, appArmorAnnotationValue)
	}

	if len(annotationKeys) > 0 {
		logrus.Infof("Pod %v applying annotation patches", pod.Name)
		annotationPatch := PatchAnnotation(pod.Annotations, annotationKeys, annotationValues)
		patches = append(patches, annotationPatch)
	}

	for container, profile := range profileMap[model.SecurityKindDrift] {
		foundCorrespondingCommandWhitelistProfile := false
		for commandWhitelistContainer, commandWhitelistProfile := range profileMap[model.SecurityKindCommandWhitelist] {
			if container == commandWhitelistContainer {
				logrus.Infof("Applying drift profile %v to container %v", profile.name, container)
				logrus.Infof("Applying command whitelist profile %v to container %v", commandWhitelistProfile.name, container)
				foundCorrespondingCommandWhitelistProfile = true
				driftPatches := PatchDriftPreventionPod(spec, pod, true, container, profile.mode, true, commandWhitelistProfile.name, commandWhitelistProfile.mode)
				patches = append(patches, driftPatches...)
			}
		}
		if !foundCorrespondingCommandWhitelistProfile {
			logrus.Infof("Applying drift profile %v to container %v", profile.name, container)
			driftPatches := PatchDriftPreventionPod(spec, pod, true, container, profile.mode, false, "", "")
			patches = append(patches, driftPatches...)
		}
	}
	for commandWhitelistContainer, commandWhitelistProfile := range profileMap[model.SecurityKindCommandWhitelist] {
		foundCorrespondingDriftProfile := false
		for container := range profileMap[model.SecurityKindDrift] {
			if container == commandWhitelistContainer {
				foundCorrespondingDriftProfile = true
			}
		}
		if !foundCorrespondingDriftProfile {
			logrus.Infof("Applying command whitelist profile %v to container %v", commandWhitelistProfile.name, commandWhitelistContainer)
			driftPatches := PatchDriftPreventionPod(spec, pod, false, commandWhitelistContainer, model.SecurityModeDetection, true, commandWhitelistProfile.name, commandWhitelistProfile.mode)
			patches = append(patches, driftPatches...)
		}
	}

	logrus.Infof("Pod %v applied patches %v", pod.Name, patches)

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
