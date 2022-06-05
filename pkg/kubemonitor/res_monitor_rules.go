package kubemonitor

import (
	"context"
	"strconv"
	"strings"

	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	corev1 "k8s.io/api/core/v1"
)

var (
	hostPathBlacklist = map[string]struct{}{
		"/":                                   {},
		"/user/bin/docker":                    {},
		"/var/run/docker.sock":                {},
		"/var/run/docker.service":             {},
		"/var/run/crio/crio.sock":             {},
		"/var/run/containerd/containerd.sock": {},
		"/proc/":                              {},
		"/proc":                               {},
	}
)

type ResourceRiskyVolumeRule struct{}

func (ResourceRiskyVolumeRule) RuleName() string {
	return "ResourceRiskyVolume"
}
func (ResourceRiskyVolumeRule) Description() map[string]string {
	return map[string]string{
		"zh": "资源下容器挂载有风险路径",
		"en": "The containers controlled by the resource have mounted risky pathes",
	}
}
func (ResourceRiskyVolumeRule) Severity() uint32 {
	return 4
}
func (ResourceRiskyVolumeRule) KVs() []ContextKV {
	return nil
}

type ContainerMountInfo struct {
	ContainerName string
	ContainerType string
	VolumeName    string
	HostPath      string
	MountPath     string
	ReadOnly      bool
}

func (ResourceRiskyVolumeRule) Match(ctx context.Context, resource *assets.TensorResource) ([]RiskSignal, error) {
	if resource == nil || resource.PodTemplate == nil {
		return nil, nil
	}
	hittedVolumes := make([]corev1.Volume, 0, 2)
	for _, vol := range resource.PodTemplate.Spec.Volumes {
		if vol.HostPath != nil {
			hitted := false
			if _, exist := hostPathBlacklist[vol.HostPath.Path]; exist {
				hitted = true
			} else if strings.Index(vol.HostPath.Path, "/proc") == 0 {
				hitted = true
			} else if strings.Index(vol.HostPath.Path, "/var/run") == 0 {
				hitted = true
			}
			if hitted {
				hittedVolumes = append(hittedVolumes, vol)
			}
		}
	}
	if len(hittedVolumes) > 0 {
		ctxs := make([]ContextKV, 1)
		ctxs[0].Key = "riskyHostPathes"
		ctxs[0].KeyMulti = map[string]string{
			"en": "Risky Mounted HostPathes",
			"zh": "风险挂载路径",
		}

		riskyMounts := make([]ContainerMountInfo, 0, 2)

		for _, ic := range resource.PodTemplate.Spec.InitContainers {
			for _, vol := range hittedVolumes {
				for _, mount := range ic.VolumeMounts {
					if mount.Name == vol.Name {
						if mount.Name == vol.Name {
							mountInfo := ContainerMountInfo{
								ContainerName: ic.Name,
								ContainerType: "InitContainer",
								VolumeName:    vol.Name,
								HostPath:      vol.HostPath.Path,
								MountPath:     mount.MountPath,
								ReadOnly:      mount.ReadOnly,
							}
							riskyMounts = append(riskyMounts, mountInfo)
						}
					}
				}
			}
		}
		for _, c := range resource.PodTemplate.Spec.Containers {
			for _, vol := range hittedVolumes {
				for _, mount := range c.VolumeMounts {
					if mount.Name == vol.Name {
						if mount.Name == vol.Name {
							mountInfo := ContainerMountInfo{
								ContainerName: c.Name,
								ContainerType: "Container",
								VolumeName:    vol.Name,
								HostPath:      vol.HostPath.Path,
								MountPath:     mount.MountPath,
								ReadOnly:      mount.ReadOnly,
							}
							riskyMounts = append(riskyMounts, mountInfo)
						}
					}
				}
			}
		}
		signals := make([]RiskSignal, 0, 2)
		for _, riskyMount := range riskyMounts {
			ctx := make([]ContextKV, 6)
			ctx[0].Key = "ContainerName"
			ctx[0].KeyMulti = map[string]string{
				"en": "Container Name",
				"zh": "容器名称",
			}
			ctx[0].DefaultValue = riskyMount.ContainerName

			ctx[1].Key = "ContainerType"
			ctx[1].KeyMulti = map[string]string{
				"en": "Container Type",
				"zh": "容器类型",
			}
			ctx[1].DefaultValue = riskyMount.ContainerType

			ctx[2].Key = "VolumeName"
			ctx[2].KeyMulti = map[string]string{
				"en": "Volume Name",
				"zh": "卷名称",
			}
			ctx[2].DefaultValue = riskyMount.VolumeName

			ctx[3].Key = "HostPath"
			ctx[3].KeyMulti = map[string]string{
				"en": "Host Path",
				"zh": "节点路径",
			}
			ctx[3].DefaultValue = riskyMount.HostPath

			ctx[4].Key = "MountPath"
			ctx[4].KeyMulti = map[string]string{
				"en": "Mount Path",
				"zh": "容器挂载目录",
			}
			ctx[4].DefaultValue = riskyMount.MountPath

			ctx[5].Key = "ReadOnly"
			ctx[5].KeyMulti = map[string]string{
				"en": "Read Only",
				"zh": "是否只读",
			}
			ctx[5].DefaultValue = strconv.FormatBool(riskyMount.ReadOnly)

			signals = append(signals, RiskSignal{
				Ctxs:          ctx,
				CtxIdentifier: strings.Join([]string{riskyMount.ContainerName, riskyMount.VolumeName}, "/"),
			})
		}

		return signals, nil
	}

	return nil, nil
}

type ResourceRiskyCapsRule struct{}

func (ResourceRiskyCapsRule) RuleName() string {
	return "ResourceRiskyCapabilities"
}
func (ResourceRiskyCapsRule) Severity() uint32 {
	return 6
}
func (ResourceRiskyCapsRule) Description() map[string]string {
	return map[string]string{
		"zh": "资源下的容器具有特别的POSIX权限",
		"en": "The containers controlled by the resource have got risky POSIX capabilities",
	}
}
func (ResourceRiskyCapsRule) KVs() []ContextKV {
	return nil
}

var (
	capabilitiesBlacklist = map[string]struct{}{
		"CAP_SETUID":     {},
		"CAP_SYS_ADMIN":  {},
		"CAP_SYS_MODULE": {},
		"CAP_SYS_PTRACE": {},
		"CAP_NET_ADMIN":  {},
		"CAP_CHOWN":      {},
		"CAP_SYS_CHROOT": {},
		"CAP_SETGID":     {},
		"CAP_MAC_ADMIN":  {},
		"CAP_BPF":        {},
		"CAP_MKNOD":      {},
	}
)

func findRiskyCapsInContainer(c corev1.Container, containerType string) []RiskSignal {
	if c.SecurityContext == nil {
		return nil
	}
	if c.SecurityContext.Capabilities == nil {
		return nil
	}
	signals := make([]RiskSignal, 0, 2)

	for _, cap := range c.SecurityContext.Capabilities.Add {
		if _, exist := capabilitiesBlacklist[string(cap)]; exist {
			ctx := make([]ContextKV, 3)
			ctx[0].Key = "ContainerName"
			ctx[0].KeyMulti = map[string]string{
				"en": "Container Name",
				"zh": "容器名称",
			}
			ctx[0].DefaultValue = c.Name

			ctx[1].Key = "ContainerType"
			ctx[1].KeyMulti = map[string]string{
				"en": "Container Type",
				"zh": "容器类型",
			}
			ctx[1].DefaultValue = containerType

			ctx[2].Key = "RiskyCapability"
			ctx[2].KeyMulti = map[string]string{
				"en": "Risky POSIX Capability",
				"zh": "存在风险的POSIX权限",
			}
			ctx[2].DefaultValue = string(cap)
			signals = append(signals, RiskSignal{
				Ctxs:          ctx,
				CtxIdentifier: strings.Join([]string{c.Name, string(cap)}, "/"),
			})
		}
	}
	return signals
}

func (ResourceRiskyCapsRule) Match(ctx context.Context, resource *assets.TensorResource) ([]RiskSignal, error) {
	if resource == nil || resource.PodTemplate == nil {
		return nil, nil
	}

	signals := make([]RiskSignal, 0, 2)
	for _, ic := range resource.PodTemplate.Spec.InitContainers {
		signals = append(signals, findRiskyCapsInContainer(ic, "InitContainer")...)
	}
	for _, c := range resource.PodTemplate.Spec.Containers {
		signals = append(signals, findRiskyCapsInContainer(c, "Container")...)
	}
	return signals, nil
}

type ResourceWithPrivContainerRule struct{}

func (ResourceWithPrivContainerRule) Severity() uint32 {
	return 7
}
func (ResourceWithPrivContainerRule) RuleName() string {
	return "ResourceWithPrivelegedContainer"
}
func (ResourceWithPrivContainerRule) Description() map[string]string {
	return map[string]string{
		"zh": "资源下的pod包含了特权容器",
		"en": "The containers controlled by the resource have privileged containers",
	}
}
func (ResourceWithPrivContainerRule) KVs() []ContextKV {
	return nil
}

func generatePriviledgedEventsFromContainer(c corev1.Container, containerType string) []RiskSignal {
	if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
		multiCtxs := make([]RiskSignal, 0, 2)
		ctx := make([]ContextKV, 3)
		ctx[0].Key = "ContainerName"
		ctx[0].KeyMulti = map[string]string{
			"en": "Container Name",
			"zh": "容器名称",
		}
		ctx[0].DefaultValue = c.Name

		ctx[1].Key = "ContainerType"
		ctx[1].KeyMulti = map[string]string{
			"en": "Container Type",
			"zh": "容器类型",
		}
		ctx[1].DefaultValue = containerType

		ctx[2].Key = "RiskyPriviledged"
		ctx[2].KeyMulti = map[string]string{
			"en": "Is Privileged",
			"zh": "是否是特权容器",
		}
		ctx[2].DefaultValue = "true"
		multiCtxs = append(multiCtxs, RiskSignal{
			Ctxs:          ctx,
			CtxIdentifier: c.Name,
		})
		return multiCtxs
	}
	return nil
}

func (ResourceWithPrivContainerRule) Match(ctx context.Context, resource *assets.TensorResource) ([]RiskSignal, error) {
	if resource == nil || resource.PodTemplate == nil {
		return nil, nil
	}

	signals := make([]RiskSignal, 0, 2)
	for _, ic := range resource.PodTemplate.Spec.InitContainers {
		signals = append(signals, generatePriviledgedEventsFromContainer(ic, "InitContainer")...)
	}
	for _, c := range resource.PodTemplate.Spec.Containers {
		signals = append(signals, generatePriviledgedEventsFromContainer(c, "Container")...)
	}

	return signals, nil
}
