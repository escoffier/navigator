package kubemonitor

import (
	"context"
	"strconv"
	"strings"

	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	corev1 "k8s.io/api/core/v1"
)

var (
	hostPathBlacklist = map[string]bool{ // path -> exactMatched. exactedMatch: true: 必须保持匹配才命中；false: 可前缀匹配。
		"/user/bin/docker":                    false,
		"/var/run/docker.sock":                true,
		"/var/run/docker.service":             true,
		"/var/run/crio/crio.sock":             true,
		"/var/run/containerd/containerd.sock": true,
		"/run/containerd/containerd.sock":     true,
		"/var/lib/kubelet":                    false,
		"/var/lib/kubelet/pki":                false,
		"/etc":                                true,
		"/etc/kubernetes":                     false,
		"/etc/kubernetes/manifests":           false,
		"/root":                               false,
		"/home/admin":                         false,
		"/proc/":                              false,
		"/proc":                               true,
		"/mnt":                                true,
		"/mnt/":                               false,
		"/boot":                               true,
		"/boot/":                              false,
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
			hpath := vol.HostPath.Path
			if strings.LastIndexByte(vol.HostPath.Path, '/') == len(vol.HostPath.Path)-1 {
				hpath = vol.HostPath.Path[:len(vol.HostPath.Path)-1]
			}
			if vol.HostPath.Path == "/" {
				hitted = true
			} else if _, exist := hostPathBlacklist[hpath]; exist {
				hitted = true
			} else {
				for key, exactMatched := range hostPathBlacklist {
					if !exactMatched && strings.Index(vol.HostPath.Path, key) == 0 {
						hitted = true
						break
					}
				}
			}

			if hitted {
				hittedVolumes = append(hittedVolumes, vol)
			}
		}
	}
	if len(hittedVolumes) > 0 {
		// 这一块代码之前未使用到。暂时先注释掉
		// ctxs := make([]ContextKV, 1)
		// ctxs[0].Key = "riskyHostPathes"
		// ctxs[0].KeyMulti = map[string]string{
		// 	"en": "Risky Mounted HostPathes",
		// 	"zh": "风险挂载路径",
		// }

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
			signals = append(signals, RiskSignal{
				// Ctxs: ctx,
				Context: map[string]string{
					"Container Name": riskyMount.ContainerName,
					"Container Type": riskyMount.ContainerType,
					"Volume Name":    riskyMount.VolumeName,
					"Host Path":      riskyMount.HostPath,
					"Mount Path":     riskyMount.MountPath,
					"Read Only":      strconv.FormatBool(riskyMount.ReadOnly),
				},
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
		"SETUID":     {},
		"SYS_ADMIN":  {},
		"SYS_MODULE": {},
		"SYS_PTRACE": {},
		"NET_ADMIN":  {},
		"CHOWN":      {},
		"SYS_CHROOT": {},
		"SETGID":     {},
		"MAC_ADMIN":  {},
		"BPF":        {},
		"MKNOD":      {},
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
			signals = append(signals, RiskSignal{
				Context: map[string]string{
					"Container Name":         c.Name,
					"Container Type":         containerType,
					"Risky POSIX Capability": string(cap),
				},
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
		"en": "The pods controlled by the resource have privileged containers",
	}
}
func (ResourceWithPrivContainerRule) KVs() []ContextKV {
	return nil
}

func generatePriviledgedEventsFromContainer(c corev1.Container, containerType string) []RiskSignal {
	if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
		multiCtxs := make([]RiskSignal, 0, 2)
		multiCtxs = append(multiCtxs, RiskSignal{
			// Ctxs:          ctx,
			Context: map[string]string{
				"Container Name": c.Name,
				"Container Type": containerType,
				"Is Privileged":  "true",
			},
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

type ResourceWithSecContextRule struct{}

func (ResourceWithSecContextRule) Severity() uint32 {
	return 4
}
func (ResourceWithSecContextRule) RuleName() string {
	return "ResourceWithCapabilitiesInSecurityContext"
}
func (ResourceWithSecContextRule) Description() map[string]string {
	return map[string]string{
		"zh": "资源下的pod开启了特殊SecurityContext下的特殊配置",
		"en": "The pods controlled by the resource have enabled special capabilities in SecurityContext",
	}
}
func (ResourceWithSecContextRule) KVs() []ContextKV {
	return nil
}

func generateSecCtxEventsFromPodSpec(spec corev1.PodSpec) []RiskSignal {
	if spec.SecurityContext == nil {
		return nil
	}
	multiCtxs := make([]RiskSignal, 0, 2)
	if spec.SecurityContext.SeccompProfile != nil && spec.SecurityContext.SeccompProfile.Type != "" && spec.SecurityContext.SeccompProfile.LocalhostProfile != nil {
		multiCtxs = append(multiCtxs, RiskSignal{
			Context: map[string]string{
				"Seccomp Enabled": "true",
				"SeccompType":     string(spec.SecurityContext.SeccompProfile.Type),
			},
			CtxIdentifier: strings.Join([]string{"pod", "seccomp"}, "-"),
		})
	}
	if spec.SecurityContext.SELinuxOptions != nil && (spec.SecurityContext.SELinuxOptions.Level != "" ||
		spec.SecurityContext.SELinuxOptions.Role != "" ||
		spec.SecurityContext.SELinuxOptions.Type != "" ||
		spec.SecurityContext.SELinuxOptions.User != "") {

		ctx := map[string]string{
			"SELinux Enabled": "true",
		}

		if spec.SecurityContext.SELinuxOptions.Level != "" {
			ctx["SELinuxLevel"] = spec.SecurityContext.SELinuxOptions.Level
		}
		if spec.SecurityContext.SELinuxOptions.User != "" {
			ctx["SELinuxUser"] = spec.SecurityContext.SELinuxOptions.User
		}
		if spec.SecurityContext.SELinuxOptions.Role != "" {
			ctx["SELinuxRole"] = spec.SecurityContext.SELinuxOptions.Role
		}
		if spec.SecurityContext.SELinuxOptions.Type != "" {
			ctx["SELinuxType"] = spec.SecurityContext.SELinuxOptions.Type
		}
		multiCtxs = append(multiCtxs, RiskSignal{
			Context:       ctx,
			CtxIdentifier: strings.Join([]string{"pod", "selinux"}, "-"),
		})
	}
	return multiCtxs
}
func generateSecCtxEventsFromContainer(c corev1.Container, containerType string) []RiskSignal {
	if c.SecurityContext != nil {
		multiCtxs := make([]RiskSignal, 0, 2)
		if c.SecurityContext.SeccompProfile != nil && c.SecurityContext.SeccompProfile.Type != "" && c.SecurityContext.SeccompProfile.LocalhostProfile != nil {
			multiCtxs = append(multiCtxs, RiskSignal{
				Context: map[string]string{
					"Container Name":  c.Name,
					"Container Type":  containerType,
					"Seccomp Enabled": "true",
					"SeccompType":     string(c.SecurityContext.SeccompProfile.Type),
				},
				CtxIdentifier: strings.Join([]string{c.Name, "seccomp"}, "-"),
			})
		}
		if c.SecurityContext.SELinuxOptions != nil && (c.SecurityContext.SELinuxOptions.Level != "" ||
			c.SecurityContext.SELinuxOptions.Role != "" ||
			c.SecurityContext.SELinuxOptions.Type != "" ||
			c.SecurityContext.SELinuxOptions.User != "") {
			ctx := map[string]string{
				"Container Name":  c.Name,
				"Container Type":  containerType,
				"SELinux Enabled": "true",
			}

			if c.SecurityContext.SELinuxOptions.Level != "" {
				ctx["SELinuxLevel"] = c.SecurityContext.SELinuxOptions.Level
			}
			if c.SecurityContext.SELinuxOptions.User != "" {
				ctx["SELinuxUser"] = c.SecurityContext.SELinuxOptions.User
			}
			if c.SecurityContext.SELinuxOptions.Role != "" {
				ctx["SELinuxRole"] = c.SecurityContext.SELinuxOptions.Role
			}
			if c.SecurityContext.SELinuxOptions.Type != "" {
				ctx["SELinuxType"] = c.SecurityContext.SELinuxOptions.Type
			}
			multiCtxs = append(multiCtxs, RiskSignal{
				Context:       ctx,
				CtxIdentifier: strings.Join([]string{c.Name, "selinux"}, "-"),
			})
		}

		return multiCtxs
	}
	return nil
}

func (ResourceWithSecContextRule) Match(ctx context.Context, resource *assets.TensorResource) ([]RiskSignal, error) {
	if resource == nil || resource.PodTemplate == nil {
		return nil, nil
	}

	signals := make([]RiskSignal, 0, 2)
	for _, ic := range resource.PodTemplate.Spec.InitContainers {
		signals = append(signals, generateSecCtxEventsFromContainer(ic, "InitContainer")...)
	}
	for _, c := range resource.PodTemplate.Spec.Containers {
		signals = append(signals, generateSecCtxEventsFromContainer(c, "Container")...)
	}
	signals = append(signals, generateSecCtxEventsFromPodSpec(resource.PodTemplate.Spec)...)

	return signals, nil
}

type ResourcesWithHostNamespaceRule struct{}

func (ResourcesWithHostNamespaceRule) RuleName() string {
	return "resourcesWithHostNamespaace"
}
func (ResourcesWithHostNamespaceRule) Description() map[string]string {
	return map[string]string{
		"zh": "资源下的pod与主机共享命名空间",
		"en": "The pods controlled by the resource have namespaces shared with the host",
	}
}
func (ResourcesWithHostNamespaceRule) KVs() []ContextKV {
	return nil
}
func (ResourcesWithHostNamespaceRule) Severity() uint32 {
	return 4
}

// Match could generate multiple events by multiple []ContextKV
func (ResourcesWithHostNamespaceRule) Match(ctx context.Context, resource *assets.TensorResource) ([]RiskSignal, error) {
	if resource == nil || resource.PodTemplate == nil {
		return nil, nil
	}
	signals := make([]RiskSignal, 0, 2)
	if resource.PodTemplate.Spec.HostIPC {
		signals = append(signals, RiskSignal{
			Context: map[string]string{
				"Use the host's ipc namespace": "true",
			},
			CtxIdentifier: "HostIPC",
		})
	}
	if resource.PodTemplate.Spec.HostNetwork {
		signals = append(signals, RiskSignal{
			Context: map[string]string{
				"Use the host's network namespace": "true",
			},
			CtxIdentifier: "HostNetwork",
		})
	}
	if resource.PodTemplate.Spec.HostPID {
		signals = append(signals, RiskSignal{
			Context: map[string]string{
				"Use the host's pid namespace": "true",
			},
			CtxIdentifier: "HostPID",
		})
	}
	return signals, nil
}

type ResourcesWithInsecureSecretsEnvRule struct{}

func (ResourcesWithInsecureSecretsEnvRule) RuleName() string {
	return "resourcesWithInsecureSecrets"
}
func (ResourcesWithInsecureSecretsEnvRule) Description() map[string]string {
	return map[string]string{
		"zh": "资源下容器的环境变量中包含直接暴露的secret",
		"en": "The containers use the env to exposure secrets/keys directly",
	}
}
func (ResourcesWithInsecureSecretsEnvRule) KVs() []ContextKV {
	return nil
}
func (ResourcesWithInsecureSecretsEnvRule) Severity() uint32 {
	return 6
}

func getCtxsWithInsecureSecretsEnvFromContainer(c corev1.Container, containerType string) []RiskSignal {
	signals := make([]RiskSignal, 0, 2)
	for _, env := range c.Env {
		if strings.Index(env.Name, "PASSWORD") >= 0 || strings.Index(env.Name, "PWD") >= 0 {
			if env.Value != "" && (env.ValueFrom == nil || env.ValueFrom.SecretKeyRef == nil) {
				signals = append(signals, RiskSignal{
					Context: map[string]string{
						"Container Name": c.Name,
						"Container Type": containerType,
						"Env Key":        env.Name,
					},
					CtxIdentifier: strings.Join([]string{c.Name, containerType, env.Name}, "-"),
				})
			}
		}
	}
	return signals
}

// Match could generate multiple events by multiple []ContextKV
func (ResourcesWithInsecureSecretsEnvRule) Match(ctx context.Context, resource *assets.TensorResource) ([]RiskSignal, error) {
	if resource == nil || resource.PodTemplate == nil {
		return nil, nil
	}
	signals := make([]RiskSignal, 0, 2)
	for _, ic := range resource.PodTemplate.Spec.InitContainers {
		signals = append(signals, getCtxsWithInsecureSecretsEnvFromContainer(ic, "InitContainer")...)
	}
	for _, c := range resource.PodTemplate.Spec.Containers {
		signals = append(signals, getCtxsWithInsecureSecretsEnvFromContainer(c, "Container")...)
	}
	return signals, nil
}

type ResourcesWithDefaultSARule struct{}

func (ResourcesWithDefaultSARule) RuleName() string {
	return "ResourcesWithDefaultSA"
}
func (ResourcesWithDefaultSARule) Description() map[string]string {
	return map[string]string{
		"zh": "资源下的pod使用了默认的ServiceAccount",
		"en": "The pods controlled by the resource use the default ServiceAccount",
	}
}
func (ResourcesWithDefaultSARule) KVs() []ContextKV {
	return nil
}
func (ResourcesWithDefaultSARule) Severity() uint32 {
	return 2
}

// Match could generate multiple events by multiple []ContextKV
func (ResourcesWithDefaultSARule) Match(ctx context.Context, resource *assets.TensorResource) ([]RiskSignal, error) {
	if resource == nil || resource.PodTemplate == nil {
		return nil, nil
	}
	signals := make([]RiskSignal, 0, 1)
	if resource.PodTemplate.Spec.ServiceAccountName == "default" {
		signals = append(signals, RiskSignal{
			// Ctxs:          []ContextKV{},
			Context:       map[string]string{},
			CtxIdentifier: "defaultSA",
		})
	}
	return signals, nil
}

type ResourcesWithRequestLimitSetRule struct{}

func (ResourcesWithRequestLimitSetRule) RuleName() string {
	return "ResourcesWithRequestLimitSet"
}
func (ResourcesWithRequestLimitSetRule) Description() map[string]string {
	return map[string]string{
		"zh": "资源下的pod的容器是否没有设置request/limit",
		"en": "The containers controlled by the resource haven't been set the request/limit",
	}
}
func (ResourcesWithRequestLimitSetRule) KVs() []ContextKV {
	return nil
}
func (ResourcesWithRequestLimitSetRule) Severity() uint32 {
	return 2
}

func getCtxsWithoutRequestLimitFromContainer(c corev1.Container, containerType string) []RiskSignal {
	signals := make([]RiskSignal, 0, 2)
	if _, exist := c.Resources.Requests[corev1.ResourceCPU]; !exist {
		signals = append(signals, RiskSignal{
			Context: map[string]string{
				"Container Name":      c.Name,
				"Container Type":      containerType,
				"requests CPU is Set": "false",
			},
			CtxIdentifier: strings.Join([]string{c.Name, containerType, "requests.cpu"}, "-"),
		})
	}
	if _, exist := c.Resources.Requests[corev1.ResourceMemory]; !exist {
		signals = append(signals, RiskSignal{
			Context: map[string]string{
				"Container Name":         c.Name,
				"Container Type":         containerType,
				"requests Memory is Set": "false",
			},
			CtxIdentifier: strings.Join([]string{c.Name, containerType, "requests.mem"}, "-"),
		})
	}
	if _, exist := c.Resources.Limits[corev1.ResourceCPU]; !exist {
		signals = append(signals, RiskSignal{
			Context: map[string]string{
				"Container Name":    c.Name,
				"Container Type":    containerType,
				"Limits CPU is Set": "false",
			},
			CtxIdentifier: strings.Join([]string{c.Name, containerType, "limits.cpu"}, "-"),
		})
	}
	if _, exist := c.Resources.Limits[corev1.ResourceMemory]; !exist {
		signals = append(signals, RiskSignal{
			Context: map[string]string{
				"Container Name":       c.Name,
				"Container Type":       containerType,
				"Limits Memory is Set": "false",
			},
			CtxIdentifier: strings.Join([]string{c.Name, containerType, "limits.mem"}, "-"),
		})
	}

	return signals
}

// Match could generate multiple events by multiple []ContextKV
func (ResourcesWithRequestLimitSetRule) Match(ctx context.Context, resource *assets.TensorResource) ([]RiskSignal, error) {
	if resource == nil || resource.PodTemplate == nil {
		return nil, nil
	}
	signals := make([]RiskSignal, 0, 2)
	for _, ic := range resource.PodTemplate.Spec.InitContainers {
		signals = append(signals, getCtxsWithoutRequestLimitFromContainer(ic, "InitContainer")...)
	}
	for _, c := range resource.PodTemplate.Spec.Containers {
		signals = append(signals, getCtxsWithoutRequestLimitFromContainer(c, "Container")...)
	}
	return signals, nil
}
