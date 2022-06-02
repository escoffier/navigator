package dp

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/container"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo"
	"gitlab.com/security-rd/go-pkg/logging"

	"github.com/docker/docker/pkg/system"
	"github.com/moby/sys/mountinfo"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/container/nsenter"
)

const (
	excludeImage = "daemon"
)

type Injector struct {
	mountInfo           mountinfo.Info
	subRoot             string
	subPath             string
	npw                 *nodeinfo.NodePodsWatcher
	excludeNamespace    []string
	containerCommandSeq [][]string
}

var (
	HostTensorPath          = "/host/tmp/tensor"
	HostEtcPreloadPath      = "/host/tmp/ld.so.preload"
	procPrefix              = "/host/proc/"
	ContainerPath           = "/.tensor"
	injectSoName            = "dp.so"
	containerTmpMnt         = "/tmpmnt"
	containerEtcPreloadPath = "/etc/ld.so.preload"
	blockDevPath            = "/dev/tensor"
)

func copyFile(src, dst string) error {
	sFile, err := os.Open(src)
	if err != nil {
		logging.Get().Error().Msgf("Failed to open ld.so.preload %v", err)
		return err
	}
	defer sFile.Close()

	dstFile, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE, 0755)
	if err != nil {
		logging.Get().Error().Msgf("Failed to open ld.so.preload %v", err)
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, sFile)

	return err
}

func (ij *Injector) prepareFiles() error {
	if _, err := os.Stat(HostTensorPath); err != nil {
		os.Mkdir(HostTensorPath, os.FileMode(0755))
	}

	err := copyFile("/tensor/ld.so.preload", HostEtcPreloadPath)
	if err != nil {
		logging.Get().Error().Msgf("Failed to copy ld.so.preload %v", err)
		return err
	}

	err = copyFile("/tensor/dp.so", HostTensorPath+"/dp.so")
	if err != nil {
		logging.Get().Error().Msgf("Failed to copy dp.so %v", err)
		return err
	}
	return nil
}

func (ij *Injector) initCommandSeq() error {
	tensorDir := containerTmpMnt + ij.subRoot + ij.subPath
	tmpCommandSeq := [][]string{
		{"mkdir", containerTmpMnt},
		{"mount", blockDevPath, containerTmpMnt},
		{"mkdir", ContainerPath},
		{"mount", "-o", "bind", tensorDir, ContainerPath},
		{"touch", containerEtcPreloadPath},
		{"mount", "-o", "bind,ro", containerTmpMnt + ij.subRoot + "/ld.so.preload", containerEtcPreloadPath},
		{"umount", containerTmpMnt},
		// {"rm", "-rf", containerTmpMnt},
	}
	ij.containerCommandSeq = tmpCommandSeq
	return nil
}

func getExcludeNamespaces() []string {

	namespaces := []string{
		"kube-system",
		"kube-public",
		"kube-node-lease",
		"kube-node-lease-renewer",
		"kube-node-lease-maintenance",
		"kube-node-lease-reclaim",
		"kube-node-lease-preemptor",
		"kube-node-lease-preemptor-maintenance",
		"kube-node-lease-preemptor-renewer",
		"kube-node-lease-preemptor-reclaim",
	}
	excludeNamespacesEnv := os.Getenv("EXCLUDE_NAMESPACES")
	if excludeNamespacesEnv != "" {
		tmpNamespaces := strings.Split(excludeNamespacesEnv, ":")
		namespaces = append(namespaces, tmpNamespaces...)

	}
	logging.Get().Info().Msgf("Exclude namespaces %v", namespaces)
	return namespaces
}

func NewInjector(npw *nodeinfo.NodePodsWatcher) (*Injector, error) {
	ij := &Injector{}

	err := ij.prepareFiles()
	if err != nil {
		logging.Get().Error().Msgf("Failed to prepare files %v", err)
		return nil, err
	}

	err = ij.getDev(HostTensorPath)
	if err != nil {
		logging.Get().Error().Msgf("Failed to get dev %v", err)
		return nil, err
	}

	err = ij.initCommandSeq()

	ij.npw = npw
	ij.excludeNamespace = getExcludeNamespaces()

	return ij, err
}

func (ij *Injector) getDev(path string) error {
	// get mount point from directory
	mountInfo, err := mountinfo.GetMounts(mountinfo.ParentsFilter(path))
	if err != nil {
		logging.Get().Err(err).Msg("Failed to get mount info")
		return err
	}
	if len(mountInfo) > 0 {
		// log.Debugf("info %+v", mountInfo[0])
		for _, v := range mountInfo {
			logging.Get().Debug().Msgf("mountInfo %+v", v)
		}
		ij.mountInfo = *mountInfo[len(mountInfo)-1]

	} else {
		return errors.New("Failed to get mount info")
	}

	ij.subRoot = ij.mountInfo.Root
	ij.subPath = strings.TrimPrefix(path, ij.mountInfo.Mountpoint)

	return nil
}

func (ij *Injector) mknodInProc(pid int) error {
	path := procPrefix + strconv.Itoa(pid) + "/root" + blockDevPath
	logging.Get().Debug().Msgf("mknod %s", path)
	dev := int(system.Mkdev(int64(ij.mountInfo.Major), int64(ij.mountInfo.Minor)))
	return syscall.Mknod(path, syscall.S_IFBLK|uint32(os.FileMode(0660)), dev)
}

func (ij *Injector) DoInject(cm container.ContainerMeta) (bool, error) {
	logging.Get().Info().Msgf("Injecting %d", cm.ProcessID)

	// excludeNamespaces
	namespace, _, err := GetContainerPodInfo(cm.ProcessID, ij.npw)
	if err != nil || namespace == "" {
		logging.Get().Error().Msgf("Failed to get container pod info %v", err)
		return false, err
	}
	for _, v := range ij.excludeNamespace {
		if v == namespace {
			logging.Get().Info().
				Str("containerID", cm.ID).
				Str("namespace", namespace).
				Msg("skip inject,namespace contains exclude namespace")
			return false, nil
		}
	}

	// check if injected
	injected, err := IsInjected(cm.ProcessID)
	if err != nil {
		logging.Get().Err(err).Str("containerID", cm.ID).Msg("container inject failed")
		return false, nil
	}
	if injected {
		logging.Get().Info().Str("containerID", cm.ID).Msg("container already injected")
		return true, nil
	}

	// inject
	config := nsenter.Config{
		Mount:     true, // Execute into mount namespace
		MountFile: fmt.Sprintf("/host/proc/%d/ns/mnt", cm.ProcessID),
		Target:    cm.ProcessID,
	}

	err = ij.mknodInProc(cm.ProcessID)
	if err != nil {
		logging.Get().Err(err).Int("ProcessID", cm.ProcessID).Str("containerdID", cm.ID).Msg("mknod failed")
	}

	for index, cmd := range ij.containerCommandSeq {
		if len(cmd) == 0 {
			break
		}
		stdout, stderr, err := config.Execute(cmd[0], cmd[1:]...)
		if err != nil {
			// encrypted log msg which contain inject detail
			msg := fmt.Sprintf("index:%d,%s,%s,%v", index, stdout, stderr, err)
			normalMsg := fmt.Sprintf("index:%d,inject failed.", index)
			EncryptedLogErrMsg(msg, logEncryptKey, normalMsg)
			break
		}
		// logging.Get().Debug().Msg(stdout)
	}

	if err != nil {
		logging.Get().
			Err(err).
			Int("processID", cm.ProcessID).
			Str("containerID", cm.ID).
			Msg("inject err")
	}

	logging.Get().
		Debug().
		Int("processID", cm.ProcessID).
		Str("containerID", cm.ID).
		Msg("inject ok")

	return IsInjected(cm.ProcessID)
}
