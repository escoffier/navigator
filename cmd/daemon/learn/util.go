package learn

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/segmentio/kafka-go"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
)

const containerProcStatus = "/host/proc/%d/status"
const containerProcCmdline = "/host/proc/%d/cmdline"
const containerProcExe = "/host/proc/%d/exe"
const containerEtcPasswd = "/host/proc/%d/root/etc/passwd"

const procStatus = "/proc/%d/status"
const procCmdline = "/proc/%d/cmdline"
const procExe = "/proc/%d/exe"
const etcPasswd = "/etc/passwd"

var selfPID *int = nil

func getSelfPID() int {
	if selfPID != nil {
		return *selfPID
	}
	pid := os.Getpid()
	selfPID = &pid
	return pid
}

type processInfo struct {
	ProcessID   int
	ProcessName string
	UID         int
	CMD         string
	Path        string
	User        string
}

func Send2Kafka(mqWrite mq.Writer, topicStr string, msg []byte) error {
	return mqWrite.Write(
		context.Background(), topicStr, kafka.Message{
			Topic: topicStr,
			Key:   []byte("learning file opt info"),
			Value: msg,
		})
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

func getProcessFromPID(pid int, isInContainer bool) processInfo {
	if pid <= 0 {
		return processInfo{}
	}
	if pid == getSelfPID() {
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

	return pi
}
