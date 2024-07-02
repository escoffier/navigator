package utils

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

const containerProcStatus = "/host/proc/%d/status"
const containerProcCmdline = "/host/proc/%d/cmdline"
const containerProcExe = "/host/proc/%d/exe"
const containerEtcPasswd = "/host/proc/%d/root/etc/passwd"
const containerProc = "/host/proc/%d/root/proc"
const containerProcCmdline2 = "/host/proc/%d/root/proc/%d/cmdline"

const procStatus = "/proc/%d/status"
const procCmdline = "/proc/%d/cmdline"
const procExe = "/proc/%d/exe"
const etcPasswd = "/etc/passwd"

type processInfo struct {
	ProcessID    int
	ProcessName  string
	UID          int
	CMD          string
	Path         string
	User         string
	ContainerPid int
}

func getUsernameByUID(uid int, pid int, isInContainer bool) (string, error) {
	// check if in container
	var passwdPath string = ""
	if isInContainer {
		passwdPath = fmt.Sprintf(containerEtcPasswd, pid)
	} else {
		passwdPath = fmt.Sprintf(etcPasswd)
	}

	file, err := os.Open(passwdPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, ":")
		if len(fields) >= 3 {
			currentUID, err := strconv.Atoi(fields[2])
			if err != nil {
				continue
			}
			if currentUID == uid {
				return fields[0], nil
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	return "", fmt.Errorf("User with UID %d not found", uid)
}

func (pi *processInfo) getProcessPIDInContainerMatch() error {
	if pi.ProcessID <= 0 {

		logging.GetLogger().Error().Msg("getProcessPIDInContainer: invalid process id")
		return fmt.Errorf("invalid process id")
	}
	if pi.CMD == "" {
		logging.GetLogger().Error().Msg("getProcessPIDInContainer: invalid process cmd")
		return fmt.Errorf("invalid process cmd")
	}
	containerProcDir := fmt.Sprintf(containerProc, pi.ProcessID)
	// hostpid pod
	_, err := os.Stat(containerProcDir + fmt.Sprintf("/%d", pi.ProcessID))
	if err == nil {
		logging.GetLogger().Info().Int("pid", pi.ProcessID).Msg("process is hostPID")
		pi.ContainerPid = pi.ProcessID
		return nil
	}
	entries, err := os.ReadDir(containerProcDir)
	if err != nil {

		logging.GetLogger().Err(err).Msg("failed to open hostProc directory")
		return err
	}
	// for hostPID
	for _, entry := range entries {
		if entry.IsDir() {
			pidStr := entry.Name()
			pid, err := strconv.Atoi(pidStr)
			if err != nil {
				logging.GetLogger().Warn().Msg("failed to convert PID")
				continue
			}
			if pid == pi.ProcessID {
				pi.ContainerPid = pid //same process id
				return nil
			}
		}
	}

	for _, entry := range entries {
		if entry.IsDir() {
			pidStr := entry.Name()
			pid, err := strconv.Atoi(pidStr)
			if err != nil {
				logging.GetLogger().Warn().Msg("failed to convert PID")
				continue
			}
			procCmdlinePath := fmt.Sprintf(containerProcCmdline2, pi.ProcessID, pid)
			data, err := os.ReadFile(procCmdlinePath)
			if err != nil {
				logging.GetLogger().Warn().Msg("failed to read cmdline")
				continue
			}
			cmdline := strings.Replace(string(data), "\x00", " ", -1)
			if strings.TrimSpace(cmdline) == pi.CMD {
				pi.ContainerPid = pid
				return nil
			}
		}
	}
	pi.ContainerPid = -1
	return fmt.Errorf("process not found in container")
}

func GetProcessFromPID(pid int, isInContainer bool) processInfo {
	if pid <= 0 {
		return processInfo{}
	}
	var procStatusPath string = ""
	if isInContainer {
		procStatusPath = fmt.Sprintf(containerProcStatus, pid)
	} else {
		procStatusPath = fmt.Sprintf(procStatus, pid)
	}
	data, err := os.ReadFile(procStatusPath)
	if err != nil {
		return processInfo{}
	}

	pi := processInfo{
		ProcessID: pid,
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "Name:" {
			pi.ProcessName = fields[1]
			continue
		}
		if len(fields) >= 2 && fields[0] == "Uid:" {
			uidStr := fields[1]
			uid, err := strconv.Atoi(uidStr)
			if err != nil {
				logging.GetLogger().Error().Msgf("getProcessFromPID: %v", err)
			}
			pi.UID = uid
			continue
		}

	}

	// get cmdline
	var procCmdlinePath string = ""
	if isInContainer {
		procCmdlinePath = fmt.Sprintf(containerProcCmdline, pid)
	} else {
		procCmdlinePath = fmt.Sprintf(procCmdline, pid)
	}
	data, err = os.ReadFile(procCmdlinePath)
	if err != nil {
		logging.GetLogger().Error().Msgf("getProcessFromPID: %v", err)
		return pi
	}
	cmdline := strings.Replace(string(data), "\x00", " ", -1)
	pi.CMD = strings.TrimSpace(cmdline)

	// get exe
	var procExePath string = ""
	if isInContainer {
		procExePath = fmt.Sprintf(containerProcExe, pid)
	} else {
		procExePath = fmt.Sprintf(procExe, pid)
	}

	exePath, err := os.Readlink(procExePath)
	if err != nil {
		logging.GetLogger().Error().Msgf("getProcessFromPID: %v", err)
		return pi
	}
	pi.Path = exePath

	// get username
	username, err := getUsernameByUID(pi.UID, pid, isInContainer)
	if err != nil {
		logging.GetLogger().Error().Msgf("getProcessFromPID: %v", err)
		return pi
	}
	pi.User = username

	// get process id in container
	if isInContainer {
		err = pi.getProcessPIDInContainerMatch()
		if err != nil {
			logging.GetLogger().Err(err).Msgf("getProcessFromPID: %v", pid)
		}

	}

	return pi
}
