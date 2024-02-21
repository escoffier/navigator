package fanotify

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/opencontainers/runtime-spec/specs-go"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"

	// "gitlab.com/piccolo_su/vegeta/pkg/until"
	"golang.org/x/sys/unix"
)

const procSelfFd = "/proc/self/fd/%d"
const containerProcSelfFd = "/host/proc/self/fd/%d"
const containerProcStatus = "/host/proc/%d/status"

const procRootMountPoint = "/proc/%d/root"
const procStatus = "/proc/%d/status"

const containerProcRootMountPoint = "/host/proc/%d/root"

//var monitorDir string = "/run/containerd/io.containerd.runtime.v2.task/moby"
//var monitorDir string = "/run/containerd"

//var monitorDir string = "/root/go"

// var monitorDir string = "/var/lib/docker/overlay2"

// mount with docker path, can't detect events when create file in docker
//var monitorDir string = "/var/lib/docker/overlay2/5ddf48777fd2bbfc730ed8357d78e48badb57471f96d7b43041c3b7b169722b2/merged"

// mount host root dir -- not work for creating file in docker
// var monitorDir string = "/"
//var monitorDirs string = "/proc/49466/root"

type faProcGrpRef struct {
	name string // parent name
	path string // parent path
	ppid int
}

// whitelist per container
type rootFd struct {
	pid int
	// id             string
	// setting        string
	// group          string
	// whlst          map[string]int // not set: -1, deny: 0, allow: 1, ....
	// dirMonitorList []string
	// allowProcList  []faProcGrpRef        // allowed process group
	// permitProcGrps map[int]*faProcGrpRef // permitted pgid and ppid
}

type FileAccessCtrl struct {
	Enabled bool
	//prober        *Probe
	ctrlMux sync.Mutex
	Fanfd   *NotifyFD
	roots   map[string]*rootFd // container id, individual control list
	// lastReportPid  int                // filtering repeated report
	// marks          int                // monitor total allocated marks
	cflag          uint64 // fanotify configuration flags( open-perm or exec-perm)
	RunInContainer bool   // true: run in container
	mountPoint     string // /proc/[pid]/root
}

func NewFileAccessCtrl(runInContainer bool) (*FileAccessCtrl, bool) {

	fa := &FileAccessCtrl{
		Enabled:        false,
		roots:          make(map[string]*rootFd),
		RunInContainer: runInContainer,
	}

	// docker cp (file changes) might change the polling behaviors,
	// remove the non-block io to controller the polling timeouts
	flags := FAN_CLASS_CONTENT | FAN_UNLIMITED_MARKS | FAN_UNLIMITED_QUEUE | FAN_NONBLOCK
	fn, err := Initialize(flags, unix.O_RDONLY|unix.O_LARGEFILE)
	if err != nil {
		logging.GetLogger().Err(err).Msg("FA: Initialize")
		return nil, false
	}

	// fill in
	fa.Enabled = true
	fa.Fanfd = fn
	logging.GetLogger().Debug().Interface("faFd", fn.GetFd()).Msg("fa info")

	if !fa.isSupportOpen() {
		fa.Enabled = false // reset it back
		return nil, false
	}

	// default: test the availability of open_permissions
	if fa.isSupportOpenPerm() {
		logging.GetLogger().Info().Msg("FA: OpenPerm is  supported")
		// fa.cflag = FAN_OPEN_PERM
	}

	// FAN_OPEN_PERM can detect operation like: echo "a" > a.txt ,while FAN_OPEN_EXEC_PERM can't
	fa.cflag |= FAN_OPEN

	// preferable flag
	if fa.isSupportExecPerm() {
		logging.GetLogger().Info().Msg("FA: ExecPerm is supported")
		// fa.cflag |= FAN_OPEN_EXEC_PERM
	}
	// we always monitor new file created, so we only need FAN_OPEN_PERM
	fa.cflag |= fa.cflag | FAN_CLOSE_WRITE | FAN_MODIFY

	// add monitor dir
	// fa.AddDirMarks(containerMeta.State.Pid, []string{monitorDir})

	// go fa.monitorFilePermissionEvents()
	return fa, true
}

func (fa *FileAccessCtrl) isSupportOpen() bool {
	var path string
	if fa.RunInContainer {
		path = fmt.Sprintf(procRootMountPoint, 1) // when in container,use pid 1
	} else {
		path = fmt.Sprintf(procRootMountPoint, os.Getpid())
	}

	err := fa.Fanfd.Mark(FAN_MARK_ADD, FAN_OPEN, unix.AT_FDCWD, path)
	_ = fa.Fanfd.Mark(FAN_MARK_REMOVE, FAN_OPEN, unix.AT_FDCWD, path)
	if err != nil {
		logging.GetLogger().Err(err).Msg("FA: FAN_OPEN not supported")
		return false
	}
	return true
}

func (fa *FileAccessCtrl) isSupportOpenPerm() bool {
	var path string
	if fa.RunInContainer {
		path = fmt.Sprintf(procRootMountPoint, 1) // when in container,use pid 1
	} else {
		path = fmt.Sprintf(procRootMountPoint, os.Getpid())
	}

	err := fa.Fanfd.Mark(FAN_MARK_ADD, FAN_OPEN_PERM, unix.AT_FDCWD, path)
	_ = fa.Fanfd.Mark(FAN_MARK_REMOVE, FAN_OPEN_PERM, unix.AT_FDCWD, path)
	if err != nil {
		logging.GetLogger().Err(err).Msg("FA: FAN_OPEN_PERM not supported")
		return false
	}
	return true
}

func (fa *FileAccessCtrl) isSupportExecPerm() bool {
	var path string
	if fa.RunInContainer {
		path = fmt.Sprintf(procRootMountPoint, 1)
	} else {
		path = fmt.Sprintf(procRootMountPoint, os.Getpid())
	}
	err := fa.Fanfd.Mark(FAN_MARK_ADD, FAN_OPEN_EXEC_PERM, unix.AT_FDCWD, path)
	_ = fa.Fanfd.Mark(FAN_MARK_REMOVE, FAN_OPEN_EXEC_PERM, unix.AT_FDCWD, path)
	if err != nil {
		logging.GetLogger().Err(err).Msg("FA: FAN_OPEN_EXEC_PERM not supported")
		return false
	}
	return true
}

func (fa *FileAccessCtrl) monitorFilePermissionEvents() {
	waitCnt := 0
	pfd := make([]unix.PollFd, 1)
	pfd[0].Fd = fa.Fanfd.GetFd()
	pfd[0].Events = unix.POLLIN
	logging.GetLogger().Debug().Interface("pfd", pfd[0]).Msg("FA: start")
	for {
		n, err := unix.Poll(pfd, 5000) // wait 5 sec
		logging.GetLogger().Debug().Msgf("poll get event:%d", n)
		if err != nil && err != unix.EINTR { // not interrupted by a signal
			logging.GetLogger().Err(err).Msg("FA: poll returns error")
			break
		}

		if n <= 0 {
			if n == 0 && !fa.Enabled { // timeout at exit stage
				waitCnt += 1
				if waitCnt > 1 { // two chances
					break
				}
			}
			continue
		}

		logging.GetLogger().Debug().Msgf("poll event:%+v", pfd[0])
		if (pfd[0].Revents & unix.POLLIN) != 0 {
			fa.handleEvents()
			waitCnt = 0
		}
	}

	fa.MonitorExit()
	logging.GetLogger().Info().Msg("FA: exit")
}

func (fa *FileAccessCtrl) handleEvents() {
	for fa.Enabled {
		ev, err := fa.Fanfd.GetEvent()
		if err != nil {
			logging.GetLogger().Err(err).Msg("handle event err")
			return
		}

		go func() {
			defer func() {
				err = ev.File.Close()
				if err != nil {
					logging.GetLogger().Err(err).Msg("ev file close err.")
				}
			}()

			// print some info
			evPid := ev.Pid
			// evProcessName, err := pkg.ProcessName(evPid, fa.runInContainer)
			if err != nil {
				logging.GetLogger().Err(err).Int32("pid", evPid).Msg("failed to get process name")
			}

			//evFileName := ev.File.Name()// filename is nil for fa.fanfd.GetEvent assign nil file name
			evFilePath, _ := EventFilePath(ev, fa.RunInContainer)
			evType := EventType(ev)

			logging.GetLogger().Debug().
				Int32("pid", evPid).
				Interface("fd", ev.File.Fd()).
				// Str("processName", evProcessName).
				//Str("fileName", evFileName).
				Str("filePath", evFilePath).
				Str("evType", evType).
				Msg("event info")

			if ev.Version != FANOTIFY_METADATA_VERSION {
				logging.GetLogger().Error().Interface("ev", ev).Msg("FA: wrong metadata version")
				return
			}

			if ev.MatchMask(FAN_OPEN_PERM) || ev.MatchMask(FAN_OPEN_EXEC_PERM) || ev.MatchMask(FAN_ACCESS_PERM) {
				logging.GetLogger().Debug().Msg("match perm events,do response")
				time.Sleep(time.Second * 10)
				err = fa.Fanfd.Response(ev, true)
				if err != nil {
					logging.GetLogger().Err(err).Msg("response allow err")
				} else {
					logging.GetLogger().Debug().Msg("response allow ok")
				}
			} else {
				logging.GetLogger().Debug().Msg("not match perm events,do nothing")
			}

		}()

	}
}

func (fa *FileAccessCtrl) lockMux() {
	// logging.GetLogger().WithFields(logging.GetLogger().Fields{"goroutine": utils.GetGID()}).Debug("FA: ")
	fa.ctrlMux.Lock()
}

func (fa *FileAccessCtrl) unlockMux() {
	fa.ctrlMux.Unlock()
	// logging.GetLogger().WithFields(logging.GetLogger().Fields{"goroutine": utils.GetGID()}).Debug("FA: ")
}

func (fa *FileAccessCtrl) MonitorExit() {
	if fa.Fanfd != nil {
		fa.Fanfd.Close()
	}
	fa.Enabled = false
	fa.Fanfd = nil

	//if fa.prober != nil {
	//	fa.prober.FaEndChan <- true
	//}
}

func (fa *FileAccessCtrl) AddDirMarks(pid int, dirs []string) (bool, int) {
	logging.GetLogger().Debug().Int("pid", pid).Interface("dirs", dirs).Msg("FA: add dir marks start")

	var procDir string
	if fa.RunInContainer {
		procDir = containerProcRootMountPoint
	} else {
		procDir = procRootMountPoint
	}

	ppath := fmt.Sprintf(procDir, pid)
	for _, dir := range dirs {
		path := ppath + dir
		err := fa.Fanfd.Mark(FAN_MARK_ADD|FAN_MARK_MOUNT, fa.cflag|FAN_EVENT_ON_CHILD, unix.AT_FDCWD, path)
		if err != nil {
			logging.GetLogger().Err(err).Str("path", path).Msg("FA: add mark failed")
		} else {
			logging.GetLogger().Debug().Str("path", path).Msg("FA: add mark ok")
		}

		// record
		_ = fa.recordRootFs(pid, path)
	}

	return true, len(dirs)
}

func (fa *FileAccessCtrl) RemoveDirMarks(pid int, dirs []string) int {
	var procDir string
	if fa.RunInContainer {
		procDir = containerProcRootMountPoint
	} else {
		procDir = procRootMountPoint
	}
	ppath := fmt.Sprintf(procDir, pid)
	for _, dir := range dirs {
		path := ppath + dir
		fa.Fanfd.Mark(FAN_MARK_REMOVE, fa.cflag|FAN_EVENT_ON_CHILD, unix.AT_FDCWD, path)
	}
	return len(dirs)
}

func (fa *FileAccessCtrl) CleanAllDirsMarks() int {
	fa.lockMux()
	defer fa.unlockMux()
	for key, rfd := range fa.roots {
		pid := rfd.pid
		fa.RemoveDirMarks(pid, []string{"/"})
		delete(fa.roots, key)
	}
	return 0
}

func (fa *FileAccessCtrl) recordRootFs(containerPID int, rootfs string) error {
	fa.lockMux()
	defer fa.unlockMux()
	_, ok := fa.roots[fmt.Sprintf("%d", containerPID)]
	if ok {
		logging.GetLogger().Warn().Int("pid", containerPID).Msg("container already recorded")
		return fmt.Errorf("container already exist.pid %d", containerPID)
	}
	fa.roots[fmt.Sprintf("%d", containerPID)] = &rootFd{
		pid: containerPID,
	}
	return nil
}

func (fa *FileAccessCtrl) setIgnoreMask(fullPath string) error {
	realPath := filepath.Join(fa.mountPoint, fullPath)
	//err := fa.fanfd.Mark(FAN_MARK_ADD|FAN_MARK_IGNORED_MASK|FAN_MARK_IGNORED_SURV_MODIFY, FAN_ALL_EVENTS|FAN_ALL_PERM_EVENTS, unix.AT_FDCWD, realPath)
	var ignore uint64 = FAN_ALL_EVENTS | FAN_OPEN_EXEC_PERM | FAN_ACCESS_PERM
	err := fa.Fanfd.Mark(FAN_MARK_ADD|FAN_MARK_IGNORED_MASK, ignore, unix.AT_FDCWD, realPath)
	return err
}

func EventFilePath(ev *EventMetadata, inContainer bool) (string, error) {
	//if inContainer {
	//	path, err := os.Readlink(fmt.Sprintf(containerProcSelfFd, ev.File.Fd()))
	//	return path, err
	//}
	path, err := os.Readlink(fmt.Sprintf(procSelfFd, ev.File.Fd()))
	return path, err
}

func EventProcessName(ev *EventMetadata, inContainer bool) (string, error) {
	pid := ev.Pid
	procStatusPath := ""

	if inContainer {
		procStatusPath = fmt.Sprintf(containerProcStatus, pid)
	} else {
		procStatusPath = fmt.Sprintf(procStatus, pid)
	}
	data, err := os.ReadFile(procStatusPath)
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "Name:" {
			return fields[1], nil
		}
	}
	return "", nil
}

func EventPPID(ev *EventMetadata, inContainer bool) int {
	pid := ev.Pid
	procStatusPath := ""

	if inContainer {
		procStatusPath = fmt.Sprintf(containerProcStatus, pid)
	} else {
		procStatusPath = fmt.Sprintf(procStatus, pid)
	}
	data, err := os.ReadFile(procStatusPath)
	if err != nil {
		logging.GetLogger().Err(err).Msg("read proc status err")
		return 0
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "PPid:" {
			parentPID, err := strconv.Atoi(fields[1])
			if err != nil {
				logging.GetLogger().Err(err).Msg("convert ppid err")
				return 0
			}
			return parentPID
		}
	}
	return 0
}

func EventType(ev *EventMetadata) string {
	var evType string

	if ev.MatchMask(FAN_OPEN_PERM) {
		evType += "FAN_OPEN_PERM"
	}
	if ev.MatchMask(FAN_OPEN_EXEC_PERM) {
		evType += " FAN_OPEN_EXEC_PERM"
	}
	if ev.MatchMask(FAN_MODIFY) {
		evType += " FAN_MODIFY"
	}
	if ev.MatchMask(FAN_CLOSE_WRITE) {
		evType += " FAN_CLOSE_WRITE"
	}
	if ev.MatchMask(FAN_CLOSE) {
		evType += " FAN_CLOSE"
	}
	if ev.MatchMask(FAN_ACCESS_PERM) {
		evType += " FAN_ACCESS_PERM"
	}
	if ev.MatchMask(FAN_OPEN) {
		evType += " FAN_OPEN"
	}

	return evType
}

func eventMatch(evFilePath, evProcessName string) bool {
	//processName := "runc"
	//processName := "containerd-shim"
	processName := "dockerd"
	configFile := "config.v2.json"
	if strings.Contains(evFilePath, configFile) && strings.Contains(evProcessName, processName) {
		return true
	}
	return false
}

func dumpEvFileContent(evFilePath string) {
	contents, err := os.ReadFile(evFilePath)
	if err != nil {
		logging.GetLogger().Err(err).Msg("dump file content err")
	} else {
		logging.GetLogger().Debug().Str("content", string(contents)).Str("file", evFilePath).Msg("ev file content")
		//logging.GetLogger().WithFields(logging.GetLogger().Fields{"file": evFilePath}).Debug("ev file content")
	}
	//tmpFile := "./config.json"
	//err = ioutil.WriteFile(tmpFile, contents, 0644)
	//if err != nil {
	//	logging.GetLogger().WithFields(logging.GetLogger().Fields{"err": err}).Debug("write bak config.json err")
	//} else {
	//	logging.GetLogger().Debug("write bak config.json ok")
	//}
}

func modifyContainerSpec(evFilePath string) error {
	spec := &specs.Spec{}
	cf, err := os.Open(evFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("JSON specification file %s not found", evFilePath)
		}
		return err
	}
	defer func() {
		_ = cf.Close()
	}()

	if err := json.NewDecoder(cf).Decode(spec); err != nil {
		return err
	}
	logging.GetLogger().Debug().Interface("spec", *spec).Interface("env", spec.Process.Env).Msg("decode config.json")

	// add ld_preload to env
	spec.Process.Env = append(spec.Process.Env, "LD_PRELOAD=/.tensor/dp.so", "TENSOR_CONSOLE=/home")
	logging.GetLogger().Debug().Interface("newEnv", spec.Process.Env).Msg("add new env")

	// overwrite
	contents, err := json.Marshal(spec)
	if err != nil {
		logging.GetLogger().Err(err).Msg("unmarshal err")
		return err
	}

	err = os.WriteFile(evFilePath, contents, 0644)
	if err != nil {
		logging.GetLogger().Err(err).Msg("update config.json err")
		return err
	}
	logging.GetLogger().Debug().Msg("modify config.json ok")

	return nil
}

func checkRuncSpec(evFilePath string) error {

	return nil
}

func dumpProcessTree(evProcessName string) {
	cmd := exec.Command("./script/dump.sh", evProcessName)
	content, err := cmd.CombinedOutput()

	if err != nil {
		logging.GetLogger().Err(err).Str("processName", evProcessName).Msg("dump process tree err")
	} else {
		logging.GetLogger().Debug().Str("processName", evProcessName).Str("tree", string(content)).Msg("dump process tree ok")
	}
}

func processMatch(evProcessName string) bool {
	if strings.Contains(evProcessName, "runc") ||
		strings.Contains(evProcessName, "containerd") ||
		strings.Contains(evProcessName, "dockerd") {
		return true
	}
	return false
}
