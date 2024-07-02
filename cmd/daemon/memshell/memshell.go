package memshell

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/container"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/utils"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
)

const (
	hostProc = "/host/proc"
	// hmjBinary                   = "/usr/local/bin/hmj"
	// hmjLicense                  = "/hmj_licence"
	// hmjContainerDirTemplate     = "/host/proc/%d/.hmj/"
	containerRootTemplate        = "/host/proc/%d/root"
	containerIDFilePathTemplate  = "/host/proc/%d/root/.container_id"
	containerTmpPathTemplate     = "/host/proc/%d/root/tmp/"
	containerUserHomeDirTemplate = "/host//proc/%d/root/home/%s"

	arthasBootJar = "/arthas/arthas-boot.jar"
	arthasLibsTar = "/arthas/arthas_libs.tar"

	arthasBootJarInTarget = "/tmp/arthas-boot.jar"
	nsenterCmdTemplate    = "nsenter -t %d -m -p -n su %s -c"       // targetPid, username
	arthasCmdTemplate     = "%s -jar /tmp/arthas-boot.jar %d -c %s" // targetPid, username, javaPath, pid, op

)

type k8sInfo struct {
	containerID      string
	runtimeNamespace string
	clusterKey       string
	namespace        string
	kind             string
	resourceName     string
}

type JavaProcessInfo struct {
	Pid            int
	pidInContainer int
	cmdline        string
	username       string
}

type MemShell struct {
	rt                  container.Runtime
	alerter             *Alert                    // for sending msg to event center
	pri                 *nodeinfo.PodResInfo      // pod info interface
	npw                 *nodeinfo.NodePodsWatcher // node info
	cim                 *k8s.ClusterInfoManager   // get cluster info
	pidContainerMap     map[int]k8sInfo
	pidContainerMapLock sync.Mutex
	javaProcessMap      map[int]JavaProcessInfo // java pid -> java process info
	javaProcessMapLock  sync.Mutex
	ruleList            []Rule
	ruleListLock        sync.Mutex
	runningScanRes      map[uint32]struct{}
	runningScanResLock  sync.Mutex
	resource2JavaMap    map[uint32][]JavaProcessInfo
	resource2JavaLock   sync.Mutex
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

	m.javaProcessMap = make(map[int]JavaProcessInfo)
	m.pidContainerMap = make(map[int]k8sInfo)
	m.ruleListLock = sync.Mutex{}
	m.runningScanRes = make(map[uint32]struct{})
	m.runningScanResLock = sync.Mutex{}
	m.resource2JavaMap = make(map[uint32][]JavaProcessInfo)
	return m, nil
}

func (m *MemShell) Start(ctx context.Context) error {

	logging.Get().Info().Msg("start memshell scan")
	var wg sync.WaitGroup

	firstRun := true
	doneFirstRun := make(chan struct{})

	wg.Add(1)
	go func() {
		defer func() {
			if err := recover(); err != nil {
				logging.Get().Err(err.(error)).Msg("panic in memshell")
			}
		}()
		defer wg.Done()
		interval := os.Getenv("MEMSHELL_UPDATE_INTERVAL")
		if interval == "" {
			interval = "30"
		}
		intervalInt, err := strconv.Atoi(interval)
		if err != nil {
			logging.Get().Err(err).Msg("failed to convert interval to int")
			intervalInt = 300
		}

		//load rule
		rules, err := ReadYAML("/etc/Memory_Horse.yaml")
		if err != nil {
			logging.Get().Err(err).Msg("failed to read yaml")
		}
		m.ruleListLock.Lock()
		m.ruleList = rules
		m.ruleListLock.Unlock()

		for {
			// record all containers
			startTime := time.Now()
			err := m.recordExistContainers()
			if err != nil {
				logging.Get().Err(err).Msg("failed to record exist java containers")
			}
			logging.Get().Info().Dur("time", time.Since(startTime)).Msg("record exist containers")
			err = m.findJavaProcessFromHostProc()
			if err != nil {
				logging.Get().Err(err).Msg("failed to find java process from host proc")
			}

			err = m.buildResource2JavaProcessMap()
			if err != nil {
				logging.Get().Err(err).Msg("failed to build resource to java process map")
			}

			if firstRun {
				logging.Get().Info().Msg("first run done")
				close(doneFirstRun)
				firstRun = false
			}

			// err = m.rt.MonitorEvent(m.runtimeEventCallback)
			// if err != nil {
			// 	logging.Get().Err(err).Msg("failed to monitor event")
			// }

			time.Sleep(time.Duration(intervalInt) * time.Second)

			m.Clean()
		}
	}()
	// configmap listen
	wg.Add(1)
	go func() {
		defer func() {
			if err := recover(); err != nil {
				logging.Get().Err(err.(error)).Msg("panic in memshell")
			}
		}()
		defer wg.Done()
		<-doneFirstRun //wait for first run
		err := m.listenConfigMap()
		if err != nil {
			logging.Get().Err(err).Msg("failed to listen configmap")
		}

	}()

	wg.Wait()
	return nil
}

func (m *MemShell) runtimeEventCallback(message *container.EventMessage) {
	// a little check
	if message == nil {
		logging.Get().Error().Msg("recv nil runtime message")
		return
	}

	logging.Get().Debug().Str("container", message.ContainerInfo.Name).Str("event", message.Event).Msg("recv runtime event")
	if message.Event == "start" {
		go func(msg *container.EventMessage) {
			defer func() {
				if r := recover(); r != nil {
					logging.Get().Error().Msgf("handle start msg panic: %v.stack:%s", r, debug.Stack())
				}
			}()
			if err := m.watchContainers([]container.ContainerMeta{msg.ContainerInfo}); err != nil {
				logging.Get().Err(err).Str("container", msg.ContainerInfo.Name).Msg("failed to watch")
			} else {
				logging.Get().Info().Str("container", msg.ContainerInfo.Name).Msg("watch end")
			}
		}(message)
	} else if message.Event == "kill" {
		// remove watch
		go func(msg *container.EventMessage) {
			defer func() {
				if r := recover(); r != nil {
					logging.Get().Error().Msgf("handle kill msg panic: %v.stack:%s", r, debug.Stack())
				}
			}()
			if err := m.removeWatchContainers([]container.ContainerMeta{msg.ContainerInfo}); err != nil {
				logging.Get().Err(err).Str("container", msg.ContainerInfo.Name).Msg("failed to remove watch")
			} else {
				logging.Get().Info().Str("container", msg.ContainerInfo.Name).Msg("remove watch ok")
			}
		}(message)

	}
}

func (m *MemShell) watchContainers(containers []container.ContainerMeta) error {
	clusterKey, ok := m.cim.ClusterKey()
	if !ok {
		logging.Get().Error().Msg("failed to get cluster key")
		return fmt.Errorf("failed to get cluster key")
	}

	for _, container := range containers {
		logging.Get().Info().Str("container", container.Name).Msg("watch container")
		if len(container.PodUID) == 0 {
			logging.Get().Warn().Msg("podUID is empty")
			continue
		}
		ev := &EventArg{}
		m.fillK8sPodInfo(container.PodUID, ev)
		m.pidContainerMapLock.Lock()
		m.pidContainerMap[container.ProcessID] = k8sInfo{
			containerID:      container.ID,
			runtimeNamespace: container.Namespace,
			namespace:        ev.Namespace,
			kind:             ev.ResourceKind,
			resourceName:     ev.ResourceName,
			clusterKey:       clusterKey,
		}
		m.pidContainerMapLock.Unlock()

		resourceUUID := util.GenerateUUID(clusterKey, ev.Namespace, ev.ResourceKind, ev.ResourceName)
		logging.Get().Info().Str("containerID", container.ID).Int("pid", container.ProcessID).Str("clusterKey", clusterKey).Str("namespace", ev.Namespace).Str("kind", ev.ResourceKind).Str("resourceName", ev.ResourceName).Msg("record container")
		putContainerID2File(container.ProcessID, container.ID)
		// wait for java process start
		time.Sleep(5 * time.Second)
		children, err := m.getChildrenProcess(container.ProcessID)
		logging.Get().Info().Int("pid", container.ProcessID).Msg("watch container start")
		if err != nil {
			logging.Get().Err(err).Int("pid", container.ProcessID).Msg("failed to get children process")
			continue
		}
		for _, child := range children {
			isJava, err := isJavaProcess(child)
			if err != nil {
				logging.Get().Err(err).Msg("failed to check if process is java")
				continue
			}
			if isJava {
				logging.Get().Info().Int("pid", child).Msg("find java process")
				procInfo := utils.GetProcessFromPID(child, true)
				m.javaProcessMapLock.Lock()
				m.javaProcessMap[child] = JavaProcessInfo{
					Pid:            child,
					cmdline:        procInfo.CMD,
					username:       procInfo.User,
					pidInContainer: procInfo.ContainerPid,
				}
				m.javaProcessMapLock.Unlock()
				m.resource2JavaLock.Lock()
				m.resource2JavaMap[resourceUUID] = append(m.resource2JavaMap[resourceUUID], JavaProcessInfo{
					Pid:            child,
					cmdline:        procInfo.CMD,
					username:       procInfo.User,
					pidInContainer: procInfo.ContainerPid,
				})
				m.resource2JavaLock.Unlock()
				logging.Get().Info().Int("pid", child).Msg("record java process")
			}
		}
		logging.Get().Info().Int("pid", container.ProcessID).Msg("watch container end")
	}
	return nil
}

func (m *MemShell) getChildrenProcess(pid int) ([]int, error) {
	children := []int{}
	path := fmt.Sprintf("%s/%d/task/%d/children", hostProc, pid, pid)
	data, err := os.ReadFile(path)
	if err != nil {
		logging.Get().Err(err).Int("pid", pid).Msg("failed to read children")
		return nil, err
	}
	value := strings.Split(string(data), " ")
	for _, v := range value {
		if len(v) == 0 {
			continue
		}
		subPid, err := strconv.Atoi(v)
		if err != nil {
			logging.Get().Err(err).Int("pid", pid).Msg("failed to convert string to int")
			continue
		}
		children = append(children, subPid)
	}

	return children, nil
}

func (m *MemShell) removeWatchContainers(containers []container.ContainerMeta) error {
	for _, container := range containers {
		m.pidContainerMapLock.Lock()
		meta := m.pidContainerMap[container.ProcessID]
		logging.Get().Info().Str("containerID", meta.containerID).Int("pid", container.ProcessID).Str("clusterKey", meta.clusterKey).Str("namespace", meta.namespace).Str("kind", meta.kind).Str("resourceName", meta.resourceName).Msg("remove container")
		resourceUUID := util.GenerateUUID(meta.clusterKey, meta.namespace, meta.kind, meta.resourceName)
		delete(m.pidContainerMap, container.ProcessID)
		m.pidContainerMapLock.Unlock()
		m.javaProcessMapLock.Lock()
		children, err := m.getChildrenProcess(container.ProcessID)
		if err != nil {
			logging.Get().Err(err).Int("pid", container.ProcessID).Msg("failed to get children process")
		}
		for _, child := range children {
			m.javaProcessMapLock.Lock()
			delete(m.javaProcessMap, child)
			m.javaProcessMapLock.Unlock()

		}
		logging.Get().Info().Int("resource UUID", int(resourceUUID)).Msg("remove container end")
		m.resource2JavaLock.Lock()
		delete(m.resource2JavaMap, resourceUUID)
		m.resource2JavaLock.Unlock()
	}

	return nil
}

func (m *MemShell) listenConfigMap() error {
	namespace := os.Getenv("MY_POD_NAMESPACE")
	if namespace == "" {
		namespace = "tensorsec"
	}

	outTime := time.Minute * 20
	timer := time.NewTimer(outTime)
	watcher, err := m.cim.HostClient.CoreV1().ConfigMaps(namespace).Watch(context.Background(), metav1.ListOptions{
		LabelSelector: model.MemshellConfigMapLabel,
	})
	if err != nil {
		logging.Get().Err(err).Msg("failed to watch configmap")
	}
	logging.Get().Info().Msg("start to watch configmap")
	for {
		select {
		case event, ok := <-watcher.ResultChan():
			if !ok {
				logging.Get().Warn().Msg("watcher closed")
				watcher.Stop()
				watcher, err = m.cim.HostClient.CoreV1().ConfigMaps(namespace).Watch(context.Background(), metav1.ListOptions{
					LabelSelector: model.MemshellConfigMapLabel,
				})
				if err != nil {
					logging.Get().Error().Msgf("watch configmap error: %v", err)
				}
				timer.Reset(outTime)
				continue
			}
			if event.Type == watch.Error {
				logging.Get().Error().Msgf("watcher error: %v", event.Object)
				continue
			}
			cm := event.Object.(*corev1.ConfigMap)
			logging.Get().Info().Str("configmap", cm.Name).Msgf("configmap %v", event.Type)
			err := m.handleConfigMap(cm)
			if err != nil {
				logging.Get().Err(err).Msg("failed to handle configmap")
			}
		case <-timer.C:
			logging.Get().Warn().Msg("watcher timeout")
			watcher.Stop()
			watcher, err = m.cim.HostClient.CoreV1().ConfigMaps(namespace).Watch(context.Background(), metav1.ListOptions{
				LabelSelector: model.MemshellConfigMapLabel,
			})
			if err != nil {
				logging.Get().Error().Msgf("watch configmap error: %v", err)
			}
		}

	}
	// return nil
}

func (m *MemShell) handleConfigMap(cm *corev1.ConfigMap) error {
	logging.Get().Info().Str("configmap", cm.Name).Msg("handle configmap")
	scanList := []uint32{}
	for k, v := range cm.Data {
		logging.Get().Info().Str("key", k).Str("value", v).Msg("configmap data")
		// scan-resource_uuid
		resourceUUID, err := strconv.Atoi(k[5:])
		if err != nil {
			logging.Get().Err(err).Str("key", k).Msg("failed to convert key to int")
			continue
		}

		// ClusterKey,Namespace,ResourceKind,Resource
		scanRes := strings.Split(v, model.MemshellConfigmapValueSplitter)
		if len(scanRes) != 5 {
			logging.Get().Error().Str("value", v).Msg("invalid value")
			continue
		}
		clusterKey := scanRes[0]
		namespace := scanRes[1]
		kind := scanRes[2]
		resourceName := scanRes[3]
		timeStamp, err := strconv.Atoi(scanRes[4])
		if err != nil {
			logging.Get().Err(err).Str("value", v).Msg("failed to convert timestamp to int")
			continue
		}
		nowTime := time.Now().Unix()
		if timeStamp < int(nowTime)-5 {
			logging.Get().Info().Str("key", k).Str("value", v).Int("now", int(nowTime)).Msg("scan resource timeout")
			continue
		}
		logging.Get().Info().Str("clusterKey", clusterKey).Str("namespace", namespace).Str("kind", kind).Str("resourceName", resourceName).Msg("add resource to scan list")
		scanList = append(scanList, uint32(resourceUUID))
	}
	m.doScanResources(scanList)
	return nil

}

func (m *MemShell) doScanResources(resourceUUID []uint32) error {
	var wg sync.WaitGroup

	for _, resUUID := range resourceUUID {

		m.runningScanResLock.Lock()
		if _, ok := m.runningScanRes[resUUID]; ok {
			logging.Get().Info().Uint32("resourceUUID", resUUID).Msg("resource already scan")
			continue
		}
		logging.Get().Info().Uint32("resourceUUID", resUUID).Msg("ready to scan resource")

		m.runningScanRes[resUUID] = struct{}{}
		m.runningScanResLock.Unlock()

		m.resource2JavaLock.Lock()
		javas, ok := m.resource2JavaMap[resUUID]
		if !ok {
			logging.Get().Error().Uint32("resourceUUID", resUUID).Msg("java process not found")
			m.runningScanResLock.Lock()
			delete(m.runningScanRes, resUUID)
			m.runningScanResLock.Unlock()
			m.resource2JavaLock.Unlock()
			continue
		}
		javaProcesses := make([]JavaProcessInfo, len(javas))

		logging.Get().Info().Uint32("resourceUUID", resUUID).Str("javaProcesses", fmt.Sprintf("%+v", javas)).Msg("java processes")
		copy(javaProcesses, javas)
		m.resource2JavaLock.Unlock()

		logging.Get().Info().Uint32("resourceUUID", resUUID).Str("javaProcesses", fmt.Sprintf("%+v", javaProcesses)).Msg("resource to scan")
		wg.Add(1)
		go func(jp []JavaProcessInfo, rID uint32) {
			defer wg.Done()
			for _, javaProcess := range jp {
				// copy arthas to container
				logging.Get().Info().Int("pid", javaProcess.Pid).Msg("copy arthas to container")
				err := m.copyArthasToContainer(javaProcess)
				if err != nil {
					logging.Get().Err(err).Interface("java process", javaProcess).Msg("failed to copy arthas to container")
					continue
				}
				// run arthas
				err = m.runArthas(javaProcess)
				if err != nil {
					logging.Get().Err(err).Int("pid", javaProcess.Pid).Msg("failed to run arthas")
				}
				err = m.rmArthasFromContainer(javaProcess)
				if err != nil {
					logging.Get().Err(err).Int("pid", javaProcess.Pid).Msg("failed to remove arthas from container")
				}
			}
			m.runningScanResLock.Lock()
			delete(m.runningScanRes, rID)
			m.runningScanResLock.Unlock()
		}(javaProcesses, resUUID)
	}
	wg.Wait()
	return nil
}

func (m *MemShell) copyArthasToContainer(javaProc JavaProcessInfo) error {

	jarBinaryPath := fmt.Sprintf(containerTmpPathTemplate, javaProc.Pid)
	username := javaProc.username
	userHomeDir := fmt.Sprintf(containerUserHomeDirTemplate, javaProc.Pid, username)

	cmdSeq := []string{
		fmt.Sprintf("cp %s %s", arthasBootJar, jarBinaryPath),
		fmt.Sprintf("tar -xf %s -C %s", arthasLibsTar, userHomeDir),
		"sync",
	}
	logging.Get().Debug().Interface("cmdSeq", cmdSeq).Msg("copy arthas to container")
	for _, cmd := range cmdSeq {
		err := exec.Command("/bin/sh", "-c", cmd).Run()
		if err != nil {
			logging.Get().Err(err).Str("run: ", cmd).Msg("failed")
			return err
		}
	}
	return nil
}

func (m *MemShell) rmArthasFromContainer(javaProc JavaProcessInfo) error {
	jarBinaryPath := fmt.Sprintf(containerTmpPathTemplate, javaProc.Pid)
	username := javaProc.username
	userHomeDir := fmt.Sprintf(containerUserHomeDirTemplate, javaProc.Pid, username)

	cmdSeq := []string{
		fmt.Sprintf("rm -f %s", jarBinaryPath),
		fmt.Sprintf("rm -rf %s", userHomeDir),
		"sync",
	}
	logging.Get().Debug().Interface("cmdSeq", cmdSeq).Msg("remove arthas from container")
	for _, cmd := range cmdSeq {
		err := exec.Command("/bin/sh", "-c", cmd).Run()
		if err != nil {
			logging.Get().Err(err).Str("run: ", cmd).Msg("failed")
			return err
		}
	}
	return nil

}

func (m *MemShell) runArthas(javaProcess JavaProcessInfo) error {
	logging.Get().Info().Int("pid", javaProcess.Pid).Msg("run arthas")
	javaCmdPath := strings.Split(javaProcess.cmdline, " ")[0]

	m.ruleListLock.Lock()
	tmpRuleList := make([]Rule, len(m.ruleList))
	copy(tmpRuleList, m.ruleList)
	m.ruleListLock.Unlock()
	clusterKey, ok := m.cim.ClusterKey()
	if !ok {
		logging.Get().Error().Msg("failed to get cluster key")
	}
	clusterName, ok := m.cim.ClusterName()
	if !ok {
		logging.Get().Error().Msg("failed to get cluster name")
	}

	for _, rule := range tmpRuleList {
		cmds := rule.Cmds
		vars := make(map[string]string) // vars result
		lastStr := ""
		logging.Get().Info().Str("ruleName", rule.Key).Msg("start rule")
		for _, cmd := range cmds {
			logging.Get().Info().Str("cmd", cmd).Msg("run command")
			lastStr = ""
			resultVar, execCmd := ParseCmdline(cmd, vars)

			logging.Get().Info().Strs("execCmd", execCmd).Str("reslutVar", resultVar).Msg("run command")
			for _, c := range execCmd {
				runCommand := fmt.Sprintf(nsenterCmdTemplate, javaProcess.Pid, javaProcess.username)
				arthasCmd := fmt.Sprintf(arthasCmdTemplate, javaCmdPath, javaProcess.pidInContainer, c)
				commandList := strings.Split(runCommand, " ")
				commandList = append(commandList, arthasCmd)
				logging.Get().Info().Strs("commandList", commandList).Msg("run arthas")
				cmdR := exec.Command(commandList[0], commandList[1:]...)
				var stdout, stderr bytes.Buffer
				cmdR.Stdout = &stdout
				cmdR.Stderr = &stderr
				err := cmdR.Run()
				if err != nil {
					logging.Get().Err(err).Str("cmd", c).Str("stdout", stdout.String()).Str("stderr", stderr.String()).Msg("failed to run command")
				}
				logging.Get().Info().Str("stdout", stdout.String()).Str("stderr", stderr.String()).Msg("command output")
				if resultVar != "" {
					vars[resultVar] += stdout.String()
				}
				lastStr += stdout.String()
			}
			if lastStr == "" {
				break
			}
		} // cmds loop
		logging.Get().Info().Str("ruleName", rule.Key).Interface("vars: ", vars).Str("lastStr", lastStr).Msg("rule done")
		if lastStr != "" {
			logging.Get().Info().Str("ruleName", rule.Key).Str("lastStr", lastStr).Msg("lastStr")
			containerID, err := os.ReadFile(fmt.Sprintf(containerIDFilePathTemplate, javaProcess.Pid))
			if err != nil {
				logging.Get().Err(err).Msg("")
			}
			m.sendAlert(clusterKey, clusterName, rule.Key, lastStr, string(containerID))
			// // if not detect other rule
			// break
		}

	}

	return nil
}

func (m *MemShell) Clean() {
	// m.pidContainerMap = make(map[int]k8sInfo)
	// m.javaProcessMap = make(map[int]JavaProcessInfo)

}

func (m *MemShell) recordExistContainers() error {
	tmpPidContainerMap := make(map[int]k8sInfo)
	containers, err := m.rt.ListRunningContainers()
	if err != nil {
		logging.Get().Err(err).Msg("failed to list all containers")
		return err
	}

	clusterKey, ok := m.cim.ClusterKey()
	if !ok {
		logging.Get().Error().Msg("failed to get cluster key")
		return fmt.Errorf("failed to get cluster key")
	}

	for _, v := range containers {
		meta, err := m.rt.GetContainerMeta(v.Namespace, v.ID)
		if err != nil && !errors.Is(err, container.ErrNotFoundPodID) {
			logging.Get().Err(err).Strs("container", v.Names).Msg("failed to get container meta")
			continue
		}
		if ki, ok := tmpPidContainerMap[meta.ProcessID]; ok {
			logging.Get().Error().Str("container", ki.containerID).Str("Pid", fmt.Sprintf("%d", meta.ProcessID)).Msg("container already exist")
		} else {

			if len(meta.PodUID) == 0 {
				logging.Get().Warn().Msg("podUID is empty")
				continue
			}
			ev := &EventArg{}
			m.fillK8sPodInfo(meta.PodUID, ev)
			tmpPidContainerMap[meta.ProcessID] = k8sInfo{
				containerID:      v.ID,
				runtimeNamespace: v.Namespace,
				namespace:        ev.Namespace,
				kind:             ev.ResourceKind,
				resourceName:     ev.ResourceName,
				clusterKey:       clusterKey,
			}
			logging.Get().Info().Str("containerID", v.ID).Int("pid", meta.ProcessID).Str("clusterKey", clusterKey).Str("namespace", ev.Namespace).Str("kind", ev.ResourceKind).Str("resourceName", ev.ResourceName).Msg("record container")
		}
		putContainerID2File(meta.ProcessID, meta.ID)
	}
	m.pidContainerMapLock.Lock()
	m.pidContainerMap = tmpPidContainerMap
	m.pidContainerMapLock.Unlock()
	return nil
}

func (m *MemShell) findJavaContainerInitProcessID(pid int) int {
	initPid := -1
	timeout := time.Now().Add(time.Second * 3).Unix()
	var err error
	// find java container init process
	for ppid := pid; ppid >= 1 && time.Now().Unix() < timeout; ppid, err = getParentProcessID(ppid) {
		if err != nil {
			logging.Get().Err(err).Int("pid", pid).Msg("failed to get parent process ID")
			break
		}
		if _, ok := m.pidContainerMap[ppid]; ok {
			initPid = ppid
			break
		}
	}
	return initPid
}

func (m *MemShell) findJavaProcessFromHostProc() error {

	entries, err := os.ReadDir(hostProc)
	if err != nil {

		logging.Get().Err(err).Msg("failed to open hostProc directory")
		return err
	}
	tmpJavaProcessMap := make(map[int]JavaProcessInfo)
	for _, entry := range entries {
		if entry.IsDir() {
			pidStr := entry.Name()
			pid, err := strconv.Atoi(pidStr)
			if err != nil {
				// logging.Get().Warn().Msg("failed to convert PID")
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
				}
				procInfo := utils.GetProcessFromPID(pid, true)
				tmpJavaProcessMap[pid] = JavaProcessInfo{
					Pid:            pid,
					cmdline:        procInfo.CMD,
					username:       procInfo.User,
					pidInContainer: procInfo.ContainerPid,
				}
			}
		}
	}

	m.javaProcessMapLock.Lock()
	m.javaProcessMap = tmpJavaProcessMap
	m.javaProcessMapLock.Unlock()
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

func (m *MemShell) buildResource2JavaProcessMap() error {
	tmpRes2JavaMap := make(map[uint32][]JavaProcessInfo)
	m.javaProcessMapLock.Lock()
	for _, javaProcess := range m.javaProcessMap {
		if javaProcess.Pid == javaProcess.pidInContainer {
			// hostPID
			logging.Get().Warn().Int("pid", javaProcess.Pid).Msg("pid equal pidInContainer")
			continue
		}
		initPid := m.findJavaContainerInitProcessID(javaProcess.Pid)
		if initPid == -1 {
			logging.Get().Error().Int("pid", javaProcess.Pid).Msg("init pid not found")
			continue
		}
		logging.Get().Info().Int("pid", javaProcess.Pid).Int("initPid", initPid).Msg("init pid")
		if k8sInfo, ok := m.pidContainerMap[initPid]; ok {
			if k8sInfo.namespace == "" {
				logging.Get().Error().Int("pid", javaProcess.Pid).Msg("namespace not found")
				continue
			}

			resourceUUID := util.GenerateUUID(k8sInfo.clusterKey, k8sInfo.namespace, k8sInfo.kind, k8sInfo.resourceName)
			tmpRes2JavaMap[resourceUUID] = append(tmpRes2JavaMap[resourceUUID], javaProcess)
			logging.Get().Info().Uint32("resourceUUID", resourceUUID).Int("pid", javaProcess.Pid).Msg("build resource2JavaMap")
		} else {
			logging.Get().Error().Int("pid", javaProcess.Pid).Msg("container id not found")
			continue
		}
	}
	m.javaProcessMapLock.Unlock()

	m.resource2JavaLock.Lock()
	for k, v := range tmpRes2JavaMap {
		m.resource2JavaMap[k] = v
	}
	for k, v := range m.resource2JavaMap {
		logging.Get().Info().Uint32("resourceUUID", k).Str("javaProcess", fmt.Sprintf("%+v", v)).Msg("resource2JavaMap")
	}
	m.resource2JavaLock.Unlock()
	logging.Get().Info().Msg("resource2JavaMap done")
	return nil
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

func (m *MemShell) sendAlert(clusterKey, clusterName, webshellType, path, containerID string) error {
	cm, error := m.rt.GetContainerMeta("", containerID)
	if error != nil {
		logging.Get().Error().Err(error).Msg("failed to get container meta")
		return error
	}

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
