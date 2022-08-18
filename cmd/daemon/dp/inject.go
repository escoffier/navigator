package dp

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
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
	// excludeImage = "daemon"
	containerIDFilePathTemplate = "/host/proc/%d/root/.container_id"
	containerBasePathTemplate   = "/host/proc/%d/root"
	supportOSConfigFilePath     = "/etc/support-os/support-os.conf"
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
	HostTensorPath              = "/host/var/lib/tensor/mnt"
	HostEtcPreloadPath          = "/host/var/lib/tensor/ld.so.preload"
	procPrefix                  = "/host/proc/"
	ContainerTensorPath         = "/.tensor"
	injectSoName                = "dp.so"
	containerTmpMnt             = "/tmpmnt"
	containerEtcPreloadPath     = "/etc/ld.so.preload"
	blockDevPath                = "/dev/tensor"
	logOutputPath               = "/tmp/drift-prevention.log"
	containerOSFilePathTemplate = []string{
		"/host/proc/%d/root/etc/os-release",
		"/host/proc/%d/root/etc/debian_release",
		"/host/proc/%d/root/etc/centos-release",
		"/host/proc/%d/root/etc/VERSION",
		"/host/proc/%d/root/etc/redhat-release",
	}

	supportOSTargets = []string{
		"ubuntu-22.04",
		"ubuntu-20.04",
		"ubuntu-18.04",
		"ubuntu-16.04",
		"debian-11",
		"debian-10",
		"debian-9",
		"centos-8",
		"centos-7",
		"rhel-8.5",
		"rhel-8.4",
		"rhel-6.5",
		"photon-4.0",
		"photon-3.0",
		"photon-2.0",
		"photon-1.0",
		"opensuse-42.3",
	}
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
		{"touch", logOutputPath},
		{"chmod", "777", logOutputPath},
		{"mkdir", containerTmpMnt},
		{"mount", blockDevPath, containerTmpMnt},
		{"mkdir", ContainerTensorPath},
		{"mount", "-o", "bind", tensorDir, ContainerTensorPath},
		{"touch", containerEtcPreloadPath},
		{"mount", "-o", "bind,ro", containerTmpMnt + ij.subRoot + "/ld.so.preload", containerEtcPreloadPath},
		{"umount", containerTmpMnt},
		{"rmdir", containerTmpMnt},
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
	logging.Get().Info().Str("ij detail", fmt.Sprintf("%v", ij)).Msg("NewInjector")
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
	initOSTargetsList(supportOSConfigFilePath)
	logging.Get().Info().Msgf("support os targets: %v", supportOSTargets)

	return nil
}

func (ij *Injector) mknodInProc(pid int) error {
	path := procPrefix + strconv.Itoa(pid) + "/root" + blockDevPath
	if err := os.RemoveAll(path); err != nil {
		logging.Get().Error().Msg(err.Error())
	}

	logging.Get().Trace().Msgf("mknod %s", path)
	dev := int(system.Mkdev(int64(ij.mountInfo.Major), int64(ij.mountInfo.Minor)))
	return syscall.Mknod(path, syscall.S_IFBLK|uint32(os.FileMode(0660)), dev)
}

func (ij *Injector) rmOldConfigBeforeInject(pid int) error {
	injectPaths := []string{fmt.Sprintf(containerBasePathTemplate, pid) + containerEtcPreloadPath,
		fmt.Sprintf(containerBasePathTemplate, pid) + ContainerTensorPath,
	}
	for _, p := range injectPaths {
		if err := os.RemoveAll(p); err != nil {
			logging.Get().Err(err).Msg("rm old path fail")
		}

	}
	return nil
}

func (ij *Injector) putContainerID2File(pid int, cid string) error {
	path := fmt.Sprintf(containerIDFilePathTemplate, pid)
	logging.Get().Trace().Msgf("put container id %s to %s", cid, path)
	return ioutil.WriteFile(path, []byte(cid), 0644)
}

func (ij *Injector) DoInject(cm container.ContainerMeta) (bool, error) {
	// logging.Get().Info().Msgf("Injecting %d", cm.ProcessID)

	if needSkipInject(cm.ProcessID) {
		logging.Get().Warn().Msgf("Skip inject %d %v", cm.ProcessID, cm.Name)
		return false, nil
	}

	// excludeNamespaces
	namespace, _, err := GetContainerPodInfo(cm.PodUID, ij.npw)
	if err != nil || namespace == "" {
		logging.Get().Error().Msgf("Failed to get container pod info %v", err)
		return false, err
	}
	for _, v := range ij.excludeNamespace {
		if v == namespace {
			// logging.Get().Info().
			// 	Str("containerID", cm.ID).
			// 	Str("namespace", namespace).
			// 	Msg("skip inject,namespace contains exclude namespace")
			return false, nil
		}
	}

	err = ij.putContainerID2File(cm.ProcessID, cm.ID)
	if err != nil {
		logging.Get().Err(err).Int("ProcessID", cm.ProcessID).Str("containerdID", cm.ID).Msg("put container id failed")
		return false, err
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
		logging.Get().Err(err).Int("ProcessID", cm.ProcessID).Str("containerID", cm.ID).Msg("mknod failed")
	}

	err = ij.rmOldConfigBeforeInject(cm.ProcessID)
	if err != nil {
		logging.Get().Warn().Int("ProcessID", cm.ProcessID).Str("containerID", cm.ID).Msg(err.Error())
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
			continue
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

	return IsInjected(cm.ProcessID)
}

func getRHELOSTargetFromFile(path string) (string, error) {
	targetStr := "rhel-"

	f, err := os.Open(path)
	if err != nil {
		logging.Get().Error().Msgf("Failed to read file %s", path)
		return "", err
	}
	defer f.Close()
	br := bufio.NewReader(f)
	for {
		line, _, c := br.ReadLine()
		if c == io.EOF {
			break
		}
		lineStr := string(line)
		splitList := strings.Split(lineStr, " ")
		if len(splitList) > 1 {
			targetStr += splitList[len(splitList)-2]
		}
	}
	return targetStr, nil
}

func getOSTargetFromFile(path string) (string, error) {
	if strings.Contains(path, "redhat-release") {
		return getRHELOSTargetFromFile(path)
	}

	targetStr := ""
	osName := ""
	osVersion := ""
	f, err := os.Open(path)
	if err != nil {
		logging.Get().Error().Msgf("Failed to read file %s", path)
		return "", err
	}
	defer f.Close()
	br := bufio.NewReader(f)
	for {
		line, _, c := br.ReadLine()
		if c == io.EOF {
			break
		}
		lineStr := string(line)
		kv := strings.Split(lineStr, "=")
		if len(kv) != 2 {
			continue
		}
		if kv[0] == "ID" {
			osName = strings.Trim(strings.Trim(strings.Trim(kv[1], "\n"), " "), "\"")
		}
		if kv[0] == "VERSION_ID" {
			osVersion = strings.Trim(strings.Trim(strings.Trim(kv[1], "\n"), " "), "\"")
		}
	}
	targetStr = osName + "-" + osVersion
	return strings.ToLower(targetStr), nil

}

func needSkipInject(pid int) bool {

	for _, v := range containerOSFilePathTemplate {
		path := fmt.Sprintf(v, pid)
		// logging.Get().Info().Msgf("try path: %v\n", path)
		if _, err := os.Stat(path); err != nil {
			continue
		}
		osTarget, err := getOSTargetFromFile(path)
		if err != nil {
			logging.Get().Error().Msgf("Failed to get os target from file %s", path)
			return true
		}

		for _, v := range supportOSTargets {
			if v == osTarget {
				// logging.Get().Info().Str("osTarget:", osTarget).Msg("")
				return false
			}
		}
		logging.Get().Info().Msgf("unknown os target %s, try to support\n", osTarget)
		break

	}

	return true
}

func initOSTargetsList(configFile string) error {
	f, err := os.Open(configFile)
	if err != nil {
		logging.Get().Warn().Msgf("Failed to read file %s", configFile)
		return err
	}
	defer f.Close()
	br := bufio.NewReader(f)
	for {
		line, _, c := br.ReadLine()
		if c == io.EOF {
			break
		}
		lineStr := strings.Trim(strings.Trim(strings.Trim(string(line), "\n"), " "), "\"")
		if lineStr == "" {
			continue
		}
		supportOSTargets = append(supportOSTargets, strings.ToLower(lineStr))
	}

	return nil
}
