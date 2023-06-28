package utils

import "gitlab.com/piccolo_su/vegeta/pkg/model"

func MergeVolumeMounts(kubeMounts, dockerMounts []model.Mounts) []model.Mounts {
	volumeMounts := make([]model.Mounts, 0, len(dockerMounts))
	if len(dockerMounts) == 0 {
		return volumeMounts
	}

	for _, dockerMount := range dockerMounts {
		
		if kubeMounts != nil {
			for _, kubeMount := range kubeMounts {
				if dockerMount.MountPath == kubeMount.MountPath {
					dockerMount.SubPath = kubeMount.SubPath
					dockerMount.SubPathExpr = kubeMount.SubPathExpr
					break
				}
			}
		}

		volumeMounts = append(volumeMounts, dockerMount)
	}

	return volumeMounts
}

func MergeContainerPorts(kubePorts, dockerPorts []model.Port, containerIP string) []model.Port {
	if len(dockerPorts) == 0 {
		return nil
	}

	ports := make([]model.Port, 0, len(dockerPorts))
	for _, dockerPort := range dockerPorts {

		if kubePorts != nil {
			for _, kubePorts := range kubePorts {
				if kubePorts.ContainerPort == dockerPort.ContainerPort {
					dockerPort.Name = kubePorts.Name
					break
				}
			}
		}

		dockerPort.ContainerIP = containerIP
		ports = append(ports, dockerPort)
	}
	return ports
}
