package mutation

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	dp "github.com/novln/docker-parser"
	"gitlab.com/piccolo_su/vegeta/cmd/webhook/pkg/processors"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	// "gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/driftprevention/v1alpha1"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type profile struct {
	name string
	mode model.SecurityMode
}

func getResources(ctx context.Context, clientset *kubernetes.Clientset, namespace string, pod *corev1.Pod) ([]model.SecurityPolicyResource, error) {

	kind := string(model.KubernetesResourcePod)
	owner := metav1.GetControllerOf(pod)
	name := ""
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

func MakePatches(ctx context.Context, spec *v1alpha1.PodPresetSpec, clientset *kubernetes.Clientset, db *gorm.DB, pod *corev1.Pod, parameters *processors.MutatorParameters) []*processors.Patch {
	resources, err := getResources(ctx, clientset, parameters.Namespace, pod)
	if err != nil {
		logging.GetLogger().Err(err).Msg("Failed to get resources")
		return nil
	}

	dbctx, dbcancel := context.WithTimeout(ctx, time.Second*10)
	defer dbcancel()

	profileMap := make(map[model.SecurityKind]map[string]profile)
	for _, kind := range []model.SecurityKind{model.SecurityKindApparmor, model.SecurityKindCommandWhitelist, model.SecurityKindSeccomp, model.SecurityKindDrift} {
		profileMap[kind] = make(map[string]profile)
	}
	for _, secPolicyResource := range resources {
		var secResource model.SecurityPolicyResource
		result := db.WithContext(dbctx).
			Where("cluster = 'default' AND kind = ? AND name = ? AND namespace = ? AND container_name = ?", secPolicyResource.Kind, secPolicyResource.Name, secPolicyResource.Namespace, secPolicyResource.ContainerName).
			First(&secResource)
		if result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				logging.GetLogger().Err(result.Error).Msg("No such resource defined in DB")
			} else {
				logging.GetLogger().Err(result.Error).Msg("Failed to get resource from DB")
			}
			continue
		}

		var p model.SecurityPolicy
		if secResource.SecurityPolicyID == nil {
			logging.GetLogger().Info().Msgf("Pod %v: no policy attached to resource %v", pod.Name, secResource)
			continue
		}
		result = db.WithContext(dbctx).Preload(clause.Associations).First(&p, *secResource.SecurityPolicyID)
		if result.Error != nil {
			logging.GetLogger().Err(result.Error).Msg("Failed to get policy from DB")
			continue
		}

		if !p.Active {
			logging.GetLogger().Info().Msgf("Pod %v: policy for %v not active", pod.Name, secResource)
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
	logging.GetLogger().Info().Msgf("Pod %v: profileMap %v", pod.Name, profileMap)
	if len(profileMap[model.SecurityKindApparmor]) == 0 && len(profileMap[model.SecurityKindCommandWhitelist]) == 0 && len(profileMap[model.SecurityKindSeccomp]) == 0 && len(profileMap[model.SecurityKindDrift]) == 0 {
		logging.GetLogger().Info().Msgf("Pod %v: no policy attached to resource", pod.Name)
		return nil
	}

	patches := make([]*processors.Patch, 0)

	annotationKeys := make([]string, 0)
	annotationValues := make([]string, 0)

	for container, profile := range profileMap[model.SecurityKindSeccomp] {
		logging.GetLogger().Info().Msgf("Applying seccomp profile %v to container %v", profile.name, container)
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
		logging.GetLogger().Error().Msgf("%v %v", seccompAnnotationKey, seccompAnnotationValue)
	}

	for container, profile := range profileMap[model.SecurityKindApparmor] {
		logging.GetLogger().Error().Msgf("Applying apparmor profile %v to container %v", profile.name, container)
		appArmorAnnotationKey := fmt.Sprintf("container.apparmor.security.beta.kubernetes.io/%s", container)
		appArmorAnnotationValue := fmt.Sprintf("localhost/%s", profile.name)
		annotationKeys = append(annotationKeys, appArmorAnnotationKey)
		annotationValues = append(annotationValues, appArmorAnnotationValue)
	}

	if len(annotationKeys) > 0 {
		logging.GetLogger().Error().Msgf("Pod %v applying annotation patches", pod.Name)
		annotationPatch := PatchAnnotation(pod.Annotations, annotationKeys, annotationValues)
		patches = append(patches, annotationPatch)
	}

	for container, profile := range profileMap[model.SecurityKindDrift] {
		foundCorrespondingCommandWhitelistProfile := false
		for commandWhitelistContainer, commandWhitelistProfile := range profileMap[model.SecurityKindCommandWhitelist] {
			if container == commandWhitelistContainer {
				logging.GetLogger().Error().Msgf("Applying drift profile %v to container %v", profile.name, container)
				logging.GetLogger().Error().Msgf("Applying command whitelist profile %v to container %v", commandWhitelistProfile.name, container)
				foundCorrespondingCommandWhitelistProfile = true
				driftPatches := PatchDriftPreventionPod(spec, pod, true, container, profile.mode, true, commandWhitelistProfile.name, commandWhitelistProfile.mode)
				patches = append(patches, driftPatches...)
			}
		}
		if !foundCorrespondingCommandWhitelistProfile {
			logging.GetLogger().Info().Msgf("Applying drift profile %v to container %v", profile.name, container)
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
			logging.GetLogger().Error().Msgf("Applying command whitelist profile %v to container %v", commandWhitelistProfile.name, commandWhitelistContainer)
			driftPatches := PatchDriftPreventionPod(spec, pod, false, commandWhitelistContainer, model.SecurityModeDetection, true, commandWhitelistProfile.name, commandWhitelistProfile.mode)
			patches = append(patches, driftPatches...)
		}
	}

	logging.GetLogger().Error().Msgf("Pod %v applied patches %v", pod.Name, patches)
	return patches
}
