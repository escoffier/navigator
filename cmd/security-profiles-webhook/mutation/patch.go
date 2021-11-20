package mutation

import (
	"fmt"

	"github.com/sirupsen/logrus"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/api/settings/v1alpha1"
)

// Patch represents a JSON patch to be applied
type Patch struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

const (
	envPatchTemplate            = "/spec/containers/%d/env"
	envPatchInitTemplate        = "/spec/initContainers/%d/env"
	volumeMountTemplate         = "/spec/containers/%d/volumeMounts"
	volumeMountInitTemplate     = "/spec/initContainers/%d/volumeMounts"
	securityContextTemplate     = "/spec/containers/%d/securityContext"
	securityContextInitTemplate = "/spec/initContainers/%d/securityContext"
	volumeTemplate              = "/spec/volumes"
	annotationPatch             = "/metadata/annotations"
)

// PatchDriftPreventionPod patches a single pod with seccomp profile annotation
func PatchDriftPreventionPod(spec *v1alpha1.PodPresetSpec, pod *corev1.Pod, drift bool, containerName string, driftMode model.SecurityMode, commandWhitelist bool, commandWhitelistProfile string, commandWhitelistMode model.SecurityMode) []*Patch {
	patches := make([]*Patch, 0)

	envs := spec.DeepCopy().Env
	if drift {
		if driftMode == model.SecurityModeDetection {
			envs = append(envs, corev1.EnvVar{
				Name:  "DRIFT_DETECT",
				Value: "true",
			})
		} else if driftMode == model.SecurityModePrevention {
			envs = append(envs, corev1.EnvVar{
				Name:  "DRIFT_PREVENT",
				Value: "true",
			})
		}
	}
	volumes := make([]corev1.Volume, 0)
	volumeName := fmt.Sprintf("cw-%s", commandWhitelistProfile)
	if commandWhitelist {
		configMapItems := make([]corev1.KeyToPath, 0)
		configMapItems = append(configMapItems, corev1.KeyToPath{
			Key:  commandWhitelistProfile,
			Path: commandWhitelistProfile,
		})
		volumes = append(volumes, corev1.Volume{
			Name: volumeName,
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					// Path: fmt.Sprintf("/var/lib/kubelet/cw/tensorsec/%s", commandWhitelistProfile),
					Path: fmt.Sprintf("/var/lib/kubelet/cw/%s", commandWhitelistProfile),
				},
			},
		})

	}
	volumePatch := PatchVolume(pod.Spec.Volumes, volumes, volumeTemplate)
	patches = append(patches, volumePatch)
	myPodNameEnvVar := corev1.EnvVar{
		Name: "MY_POD_NAME",
		ValueFrom: &corev1.EnvVarSource{
			FieldRef: &corev1.ObjectFieldSelector{
				FieldPath: "metadata.name",
			},
		},
	}
	envs = append(envs, myPodNameEnvVar)

	myPodNamespaceEnvVar := corev1.EnvVar{
		Name: "MY_POD_NAMESPACE",
		ValueFrom: &corev1.EnvVarSource{
			FieldRef: &corev1.ObjectFieldSelector{
				FieldPath: "metadata.namespace",
			},
		},
	}
	envs = append(envs, myPodNamespaceEnvVar)

	myPodUIDEnvVar := corev1.EnvVar{
		Name: "MY_POD_UID",
		ValueFrom: &corev1.EnvVarSource{
			FieldRef: &corev1.ObjectFieldSelector{
				FieldPath: "metadata.uid",
			},
		},
	}
	envs = append(envs, myPodUIDEnvVar)
	// volumeMounts := spec.DeepCopy().VolumeMounts
	volumeMounts := make([]corev1.VolumeMount, 0)
	if commandWhitelist {
		if commandWhitelistMode == model.SecurityModeDetection {
			envs = append(envs, corev1.EnvVar{
				Name:  "COMMAND_DRIFT_DETECT",
				Value: "true",
			})
		} else if commandWhitelistMode == model.SecurityModePrevention {
			envs = append(envs, corev1.EnvVar{
				Name:  "COMMAND_DRIFT_PREVENT",
				Value: "true",
			})
		}
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name: volumeName,
			// MountPath: "/tensorsec/commands.txt",
			MountPath: "/tmp/commands.txt",
			ReadOnly:  true,
		})
	}

	for i, container := range pod.Spec.Containers {
		if containerName == container.Name {
			volumeMountPatch := PatchVolumeMount(container.VolumeMounts, volumeMounts, fmt.Sprintf(volumeMountTemplate, i))
			patches = append(patches, volumeMountPatch)

			envPatch := PatchEnvVar(container.Env, envs, fmt.Sprintf(envPatchTemplate, i))
			patches = append(patches, envPatch)
		}
	}
	for i, container := range pod.Spec.InitContainers {
		if containerName == container.Name {

			volumeMountPatch := PatchVolumeMount(container.VolumeMounts, volumeMounts, fmt.Sprintf(volumeMountInitTemplate, i))
			patches = append(patches, volumeMountPatch)

			envPatch := PatchEnvVar(container.Env, envs, fmt.Sprintf(envPatchInitTemplate, i))
			patches = append(patches, envPatch)
		}
	}

	return patches
}

// PatchAnnotation creates a patch for updating a pod annotation.
func PatchAnnotation(source map[string]string, keys []string, values []string) *Patch {
	idx := make(map[string]bool)
	for k := range source {
		idx[k] = true
	}

	annotations := make(map[string]string)
	for i, key := range keys {
		if _, exists := source[key]; !exists {
			annotations[key] = values[i]
		}
	}

	return &Patch{
		Op:    "add",
		Path:  annotationPatch,
		Value: annotations,
	}
}

// PatchEnvVar creates a patch for updating a containers environment variables.
func PatchEnvVar(source, added []corev1.EnvVar, base string) *Patch {
	idx := make(map[string]bool)
	for _, src := range source {
		idx[src.Name] = true
	}

	envVars := make([]corev1.EnvVar, 0)

	for _, add := range added {
		if _, exists := idx[add.Name]; exists {
			// already exists on source, skip
			continue
		}
		idx[add.Name] = true

		envVars = append(envVars, add)
	}

	envVars = append(envVars, source...)

	return &Patch{
		Op:    "add",
		Path:  base,
		Value: envVars,
	}
}

func PatchSecurityContext(pod *corev1.Pod, containerName, profileName string) *Patch {
	for i, container := range pod.Spec.Containers {
		if containerName == container.Name {
			if pod.Spec.Containers[i].SecurityContext == nil {
				pod.Spec.Containers[i].SecurityContext = &corev1.SecurityContext{}
			}

			if pod.Spec.Containers[i].SecurityContext.SeccompProfile != nil {
				logrus.Infof("Seccomp security profile already exists in %v %s", pod, containerName)
				return nil
			}
			pod.Spec.Containers[i].SecurityContext.SeccompProfile = &corev1.SeccompProfile{
				Type:             corev1.SeccompProfileTypeLocalhost,
				LocalhostProfile: &profileName,
			}

			return &Patch{
				Op:    "add",
				Path:  fmt.Sprintf(securityContextTemplate, i),
				Value: pod.Spec.Containers[i].SecurityContext,
			}
		}
	}
	for i, container := range pod.Spec.InitContainers {
		if containerName == container.Name {
			if pod.Spec.Containers[i].SecurityContext == nil {
				pod.Spec.Containers[i].SecurityContext = &corev1.SecurityContext{}
			}

			if pod.Spec.Containers[i].SecurityContext.SeccompProfile != nil {
				logrus.Infof("Seccomp security profile already exists in %v %s", pod, containerName)
				return nil
			}
			pod.Spec.Containers[i].SecurityContext.SeccompProfile = &corev1.SeccompProfile{
				Type:             corev1.SeccompProfileTypeLocalhost,
				LocalhostProfile: &profileName,
			}

			return &Patch{
				Op:    "add",
				Path:  fmt.Sprintf(securityContextInitTemplate, i),
				Value: pod.Spec.Containers[i].SecurityContext,
			}
		}
	}
	return nil
}

// PatchVolumeMount creates a patch for updating a containers volume mounts.
func PatchVolumeMount(source, added []corev1.VolumeMount, base string) *Patch {
	idx := make(map[string]bool)
	for _, src := range source {
		idx[src.Name] = true
	}

	volumeMounts := make([]corev1.VolumeMount, 0)

	for _, add := range added {
		if _, exists := idx[add.Name]; exists {
			// already exists on source, skip
			continue
		}
		idx[add.Name] = true

		volumeMounts = append(volumeMounts, add)
	}

	volumeMounts = append(volumeMounts, source...)

	return &Patch{
		Op:    "add",
		Path:  base,
		Value: volumeMounts,
	}
}

// PatchVolume creates a patch for updating a pod volumes.
func PatchVolume(source, added []corev1.Volume, base string) *Patch {
	idx := make(map[string]bool)
	for _, src := range source {
		idx[src.Name] = true
	}

	volumes := make([]corev1.Volume, 0)

	for _, add := range added {
		if _, exists := idx[add.Name]; exists {
			// already exists on source, skip
			continue
		}
		idx[add.Name] = true

		volumes = append(volumes, add)
	}

	volumes = append(volumes, source...)

	return &Patch{
		Op:    "add",
		Path:  base,
		Value: volumes,
	}
}

func PatchAnnotations(source, added []corev1.Volume, base string) *Patch {
	idx := make(map[string]bool)
	for _, src := range source {
		idx[src.Name] = true
	}

	volumes := make([]corev1.Volume, 0)

	for _, add := range added {
		if _, exists := idx[add.Name]; exists {
			// already exists on source, skip
			continue
		}
		idx[add.Name] = true

		volumes = append(volumes, add)
	}

	volumes = append(volumes, source...)

	return &Patch{
		Op:    "add",
		Path:  base,
		Value: volumes,
	}
}
