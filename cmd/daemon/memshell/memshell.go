package memshell

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/container"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/container/nsenter"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/security-rd/go-pkg/logging"
)

const (
	hostProc                    = "/host/proc"
	hmjBinary                   = "/usr/local/bin/hmj"
	hmjLicense                  = "/hmj_licence"
	hmjContainerDirTemplate     = "/host/proc/%d/.hmj/"
	containerIDFilePathTemplate = "/host/proc/%d/root/.container_id"
)

type MemShell struct {
	rt              container.Runtime
	alerter         *Alert                    // for sending msg to event center
	pri             *nodeinfo.PodResInfo      // pod info interface
	npw             *nodeinfo.NodePodsWatcher // node info
	cim             *k8s.ClusterInfoManager   // get cluster info
	pidContainerMap map[int]string
	disjointSet     map[int]int
	javaProcessList []int
}

func NewMemShell(ops ...OptionFunc) (*MemShell, error) {
	logging.Get().Info().Msg("create memshell")
	m := &MemShell{}
	for _, op := range ops {
		op(m)
	}
	// runtime interface
	rt, err := container.CreateRuntimeCli()
	if err != nil {
		logging.Get().Err(err).Msg("failed to create runtime interface")
		return nil, err
	}
	m.rt = rt

	// alerter
	a, err := NewAlert()
	if err != nil {
		logging.Get().Err(err).Msg("failed to create alerter")
		return nil, err
	}
	m.alerter = a

	m.pidContainerMap = make(map[int]string)
	m.disjointSet = make(map[int]int)
	return m, nil
}

func (m *MemShell) Start(ctx context.Context) error {

	logging.Get().Info().Msg("start memshell scan")
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer func() {
			if err := recover(); err != nil {
				logging.Get().Err(err.(error)).Msg("panic in memshell")
			}
		}()
		interval := os.Getenv("MEMSHELL_SCAN_INTERVAL")
		if interval == "" {
			interval = "300"
		}
		intervalInt, err := strconv.Atoi(interval)
		if err != nil {
			logging.Get().Err(err).Msg("failed to convert interval to int")
			intervalInt = 300
		}
		ticker := time.NewTicker(time.Duration(intervalInt) * time.Second)
		for {

			// record all containers
			err := m.recordExistContainers()
			if err != nil {
				logging.Get().Err(err).Msg("failed to record exist java containers")
			}
			err = m.findJavaProcessFromHostProc()
			if err != nil {
				logging.Get().Err(err).Msg("failed to find java process from host proc")
			}

			m.cleanCrontabJob()

			err = m.setScanJobHostCrontab()
			if err != nil {
				logging.Get().Err(err).Msg("failed to set scan job host crontab")
			}

			m.findJavaContainerID()
			time.Sleep(2 * time.Minute)

			m.cleanCrontabJob()

			err = m.collectAndSendHmjResult()
			if err != nil {
				logging.Get().Err(err).Msg("failed to collect and send hmj result")
			}

			m.Clean()

			<-ticker.C
		}
	}()
	wg.Wait()
	return nil
}

func (m *MemShell) Clean() {
	m.disjointSet = make(map[int]int)
	m.pidContainerMap = make(map[int]string)
	m.javaProcessList = []int{}

}

func (m *MemShell) recordExistContainers() error {
	containers, err := m.rt.ListRunningContainers()
	if err != nil {
		logging.Get().Err(err).Msg("failed to list all containers")
		return err
	}

	for _, v := range containers {
		meta, err := m.rt.GetContainerMeta(v.Namespace, v.ID)
		if err != nil && !errors.Is(err, container.ErrNotFoundPodID) {
			logging.Get().Err(err).Interface("container", v.Names).Msg("failed to get container meta")
			continue
		}
		if containerId, ok := m.pidContainerMap[meta.ProcessID]; ok {
			logging.Get().Error().Str("container", containerId).Str("Pid", fmt.Sprintf("%d", meta.ProcessID)).Msg("container already exist")
		} else {
			m.pidContainerMap[meta.ProcessID] = meta.ID
		}
		putContainerID2File(meta.ProcessID, meta.ID)
	}

	return nil
}

func (m *MemShell) findJavaProcessFromHostProc() error {

	entries, err := os.ReadDir(hostProc)
	if err != nil {

		logging.Get().Err(err).Msg("failed to open hostProc directory")
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			pidStr := entry.Name()
			pid, err := strconv.Atoi(pidStr)
			if err != nil {
				logging.Get().Warn().Msg("failed to convert PID")
				continue
			}
			isJava, err := isJavaProcess(pid)
			if err != nil {
				logging.Get().Err(err).Msg("failed to check if process is java")
				continue
			}
			if isJava {
				logging.Get().Info().Int("pid", pid).Msg("find java process")
				if _, ok := m.pidContainerMap[pid]; ok {
					logging.Get().Error().Int("pid", pid).Msg("java process already exist")
				} else {
					m.javaProcessList = append(m.javaProcessList, pid)
					putHmj2Container(pid)
				}
			}

			if err != nil {
				logging.Get().Err(err).Msg("failed to get parent process ID")
				continue
			}
			if _, ok := m.disjointSet[pid]; ok {
				continue
			}
			if _, ok := m.pidContainerMap[pid]; !ok {
				ppid, err := getParentProcessID(pid)
				if err != nil {
					logging.Get().Err(err).Msg("failed to get parent process ID")
					continue
				}
				m.disjointSet[pid] = ppid
			} else {
				m.disjointSet[pid] = pid
			}

		}
	}
	return nil
}

func isJavaProcess(pid int) (bool, error) {
	pidStr := strconv.Itoa(pid)

	cmdlinePath := filepath.Join(hostProc, pidStr, "cmdline")
	cmdlineBytes, err := os.ReadFile(cmdlinePath)
	if err != nil {
		return false, err
	}

	cmdline := string(cmdlineBytes)

	if strings.Contains(cmdline, "java") {
		return true, nil
	}
	return false, nil
}

func getParentProcessID(pid int) (int, error) {
	statPath := filepath.Join(hostProc, strconv.Itoa(pid), "stat")
	statBytes, err := os.ReadFile(statPath)
	if err != nil {
		return 0, err
	}
	statStr := string(statBytes)
	statParts := strings.Fields(statStr)
	ppid, err := strconv.Atoi(statParts[3])
	if err != nil {
		return 0, err
	}
	return ppid, nil
}

func putHmj2Container(pid int) {

	containerRoot := filepath.Join(hostProc, strconv.Itoa(pid), "root")
	cmdSeq := []string{fmt.Sprintf("mkdir %s -p", containerRoot+"/.hmj"),
		fmt.Sprintf("cp %s %s", hmjBinary, containerRoot+"/.hmj"),
		fmt.Sprintf("chmod +x %s", containerRoot+"/.hmj/hmj"),
		fmt.Sprintf("mkdir %s -p", containerRoot+"/opt"),
		fmt.Sprintf("cp %s %s", hmjLicense, containerRoot+"/opt/.hmj_licence"),
		"sync",
	}
	for _, cmd := range cmdSeq {
		err := exec.Command("/bin/sh", "-c", cmd).Run()
		if err != nil {
			logging.Get().Err(err).Msg("failed to execute command")
		}
	}
}

func (m *MemShell) runHmjScan() error {
	var wg sync.WaitGroup
	ch := make(chan struct{}, 3)
	for _, pid := range m.javaProcessList {
		logging.Get().Info().Int("pid", pid).Int("containerPid", m.disjointSet[pid]).Msg("start to scan")
		ch <- struct{}{}
		containerPid := m.disjointSet[pid]
		config := nsenter.Config{
			IPC:       true,
			IPCFile:   fmt.Sprintf("/host/proc/%d/ns/ipc", containerPid),
			Mount:     true, // Execute into mount namespace
			MountFile: fmt.Sprintf("/host/proc/%d/ns/mnt", containerPid),
			Net:       true,
			NetFile:   fmt.Sprintf("/host/proc/%d/ns/net", containerPid),
			PID:       true,
			PIDFile:   fmt.Sprintf("/host/proc/%d/ns/pid", containerPid),
			// User:      true,
			// UserFile:  fmt.Sprintf("/host/proc/%d/ns/user", containerPid),
			// UTS:     true,
			// UTSFile: fmt.Sprintf("/host/proc/%d/ns/uts", containerPid),

			Target: containerPid,
		}
		wg.Add(1)
		go func(cfg nsenter.Config) {
			defer wg.Done()
			outStr, errStr, err := cfg.Execute("/.hmj/hmj", "javascan", "--output", "/.hmj")
			if err != nil {
				logging.Get().Err(err).Msg("failed to execute hmj")
			}
			logging.Get().Info().Str("output", outStr).Str("error", errStr).Msg("hmj output")
			<-ch
		}(config)
	}
	wg.Wait()

	return nil
}

func (m *MemShell) setScanJobHostCrontab() error {
	hostCrontabFile := "/host/etc/crontab"
	fInfo, err := os.Stat(hostCrontabFile)
	if err != nil {
		return err
	}
	fileMode := fInfo.Mode()
	hostCrontabBytes, err := os.ReadFile(hostCrontabFile)
	if err != nil {
		return err
	}

	containerVisited := make(map[int]struct{})

	hostCrontabStr := string(hostCrontabBytes)
	header := "\n#tensor hmj scan job\n"
	hostCrontabStr += header
	runCommandTemplate := "* * * * * root nsenter --target %d --ip=/proc/%d/ns/ipc --mount=/proc/%d/ns/mnt --net=/proc/%d/ns/net --pid=/proc/%d/ns/pid  /.hmj/hmj javascan --output /.hmj\n"
	for _, pid := range m.javaProcessList {
		containerPid := m.disjointSet[pid]
		if _, ok := containerVisited[containerPid]; ok {
			continue
		}
		runCommand := fmt.Sprintf(runCommandTemplate, containerPid, containerPid, containerPid, containerPid, containerPid)
		hostCrontabStr += header + runCommand
		containerVisited[containerPid] = struct{}{}
	}
	endFlag := "#end tensor hmj scan job\n"
	hostCrontabStr += endFlag

	err = os.WriteFile(hostCrontabFile, []byte(hostCrontabStr), fileMode)
	return err
}

func (m *MemShell) cleanCrontabJob() error {
	hostCrontabFile := "/host/etc/crontab"
	fInfo, err := os.Stat(hostCrontabFile)
	if err != nil {
		return err
	}
	fileMode := fInfo.Mode()
	hostCrontabBytes, err := os.ReadFile(hostCrontabFile)
	if err != nil {
		return err
	}
	hostCrontabStr := string(hostCrontabBytes)
	startIndex := strings.Index(hostCrontabStr, "#tensor hmj scan job")
	endIndex := strings.Index(hostCrontabStr, "#end tensor hmj scan job")
	if startIndex == -1 || endIndex == -1 {
		return nil
	}
	hostCrontabStr = hostCrontabStr[:startIndex] + hostCrontabStr[endIndex+len("#end tensor hmj scan job"):]
	err = os.WriteFile(hostCrontabFile, []byte(hostCrontabStr), fileMode)
	return err
}

func (m *MemShell) findJavaContainerID() error {
	for _, pid := range m.javaProcessList {
		containerInitPid, found := m.findParentNodeAndMerge(pid)
		if found {
			if _, ok := m.pidContainerMap[containerInitPid]; !ok {
				logging.Get().Error().Int("pid", containerInitPid).Msg("container init pid not found")
			} else {
				m.pidContainerMap[pid] = m.pidContainerMap[containerInitPid]
			}
		}
	}
	return nil
}

func (m *MemShell) findParentNodeAndMerge(pid int) (int, bool) {
	if ppid, ok := m.disjointSet[pid]; ok {
		if ppid == pid {
			return pid, true
		}
		tmpPid, exist := m.findParentNodeAndMerge(ppid)
		if exist {
			// merge path
			m.disjointSet[pid] = tmpPid
		}
		return tmpPid, exist
	}
	return 0, false
}

func (m *MemShell) collectAndSendHmjResult() error {
	containersFlag := make(map[string]struct{})
	for _, pid := range m.javaProcessList {
		if containerId, ok := m.pidContainerMap[pid]; ok {
			if _, ok := containersFlag[containerId]; ok {
				logging.Get().Info().Str("container id", containerId).Msg("container id already sent")
				continue
			}
			m.sendHmjResult(pid, containerId)
			containersFlag[containerId] = struct{}{}
		} else {
			logging.Get().Error().Int("pid", pid).Msg("container id not found")
		}
	}

	return nil
}

func (m *MemShell) sendHmjResult(pid int, containerId string) error {
	hmjResultPath := filepath.Join(hostProc, strconv.Itoa(pid), "root", ".hmj", "result.csv")
	hmjResultBytes, err := os.ReadFile(hmjResultPath)
	if err != nil {
		return err
	}
	hmjResult := string(hmjResultBytes)
	logging.Get().Info().Str("hmj result", hmjResult).Msg("hmj result")

	clusterKey, ok := m.cim.ClusterKey()
	if !ok {
		logging.Get().Error().Msg("failed to get cluster key")
		return fmt.Errorf("failed to get cluster key")
	}
	clusterName, ok := m.cim.ClusterName()
	if !ok {
		logging.Get().Error().Msg("failed to get cluster name")
		return fmt.Errorf("failed to get cluster name")
	}

	cm, error := m.rt.GetContainerMeta("", containerId)
	if error != nil {
		logging.Get().Error().Err(error).Msg("failed to get container meta")
		return error
	}

	if len(hmjResult) > 0 {
		resultLines := strings.Split(hmjResult, "\n")
		for _, line := range resultLines[1:] {
			if len(line) == 0 {
				continue
			}
			lineParts := strings.Split(line, ",")
			if len(lineParts) < 3 {
				logging.Get().Error().Str("line", line).Msg("invalid hmj result line")
				continue
			}
			webshellType := lineParts[1]
			path := lineParts[2]
			err := m.sendAlert(clusterKey, clusterName, webshellType, path, cm)
			if err != nil {
				logging.Get().Err(err).Msg("failed to send alert")
			}

		}
	}
	os.Remove(hmjResultPath)
	return nil
}

func (m *MemShell) sendAlert(clusterKey, clusterName, webshellType, path string, cm container.ContainerMeta) error {
	ev := &EventArg{
		Path:          path,
		ContainerID:   cm.ID,
		ContainerName: cm.Name,
		Hostname:      m.npw.NodeName,
		ClusterID:     clusterKey,
		Cluster:       clusterName,
		WebshellType:  webshellType,
	}
	if len(cm.PodUID) == 0 {
		logging.Get().Debug().Msg("raw container")
		// raw container
		return m.alerter.Send(ev)
	}

	// for k8s
	if err := m.fillK8sPodInfo(cm.PodUID, ev); err != nil {
		logging.Get().Err(err).Msg("failed to fill pod info to event")
		return err
	}

	return m.alerter.Send(ev)
}

func (m *MemShell) fillK8sPodInfo(podID string, ev *EventArg) error {
	// pod info
	ev.PodUID = podID

	// k8s pod info
	podInfo, err := m.npw.GetPodByUID(podID)
	if err != nil {
		logging.Get().Err(err).Msg("failed to get pod info")
		return err
	}
	ev.PodName = podInfo.Name
	ev.Namespace = podInfo.Namespace

	// k8s resource info
	resource, ok := m.pri.GetPod(podInfo.Namespace, podInfo.Name)
	if !ok {
		logging.Get().Error().Str("podName", podInfo.Name).Msg("failed to get pod resource")
		return fmt.Errorf("failed to get pod resource")
	}
	ev.ResourceKind = resource.Kind
	ev.ResourceName = resource.Name

	return nil
}

func putContainerID2File(pid int, cid string) error {
	path := fmt.Sprintf(containerIDFilePathTemplate, pid)
	logging.Get().Trace().Msgf("put container id %s to %s", cid, path)
	return os.WriteFile(path, []byte(cid), 0644)
}
