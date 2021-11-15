package main

// Before using it auditd needs to be disabled on host: `/usr/sbin/service auditd stop`

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"gitlab.com/security-rd/go-pkg/pb"

	"gitlab.com/piccolo_su/vegeta/cmd/go-audit/pkg/utils/alert"
	eventcenter_helper "gitlab.com/piccolo_su/vegeta/cmd/go-audit/pkg/utils/eventcenter-helper"
	"gitlab.com/piccolo_su/vegeta/pkg/uuid"

	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"

	libaudit "github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/auparse"
)

var (
	fs          = flag.NewFlagSet("audit", flag.ExitOnError)
	rate        = fs.Uint("rate", 0, "rate limit in kernel (default 0, no rate limit)")
	backlog     = fs.Uint("backlog", 8192, "backlog limit")
	receiveOnly = fs.Bool("ro", false, "receive only using multicast, requires kernel 3.16+")
)

const (
	mountInfoPathTemplate = "/host/proc/%d/mountinfo"
)

type Reporter struct {
	uuidGenerator *uuid.Generator
	cli           pb.EventsCenterCollectionServiceClient
}

func main() {
	fs.Parse(os.Args[1:])

	// TODO: need to be done manually (depends on the OS)

	// cmd := exec.Command("service", "auditd", "stop")
	// stderr := &bytes.Buffer{}
	// cmd.Stderr = stderr
	// out, err := cmd.Output()
	// logging.GetLogger().Info().Str("out", string(out)).Str("stderr", fmt.Sprintf("%v\n", stderr)).Msg("Stopping auditd service")
	// if err != nil {
	// 	logging.GetLogger().Error().Err(err).Msg("Failed to stop auditd service")
	// } else {
	// 	logging.GetLogger().Info().Msg("Successfully stopped auditd service")
	// }

	if err := read(); err != nil {
		log.Fatalf("error: %v", err)
	}
}

func read() error {
	if os.Geteuid() != 0 {
		return errors.New("you must be root to receive audit data")
	}

	logging.GetLogger().Info().Msg("starting netlink client")

	var err error
	var client *libaudit.AuditClient
	if *receiveOnly {
		client, err = libaudit.NewMulticastAuditClient(nil)
		if err != nil {
			return errors.Wrap(err, "failed to create receive-only audit client")
		}
		defer client.Close()
	} else {
		client, err = libaudit.NewAuditClient(nil)
		if err != nil {
			return errors.Wrap(err, "failed to create audit client")
		}
		defer client.Close()

		status, err := client.GetStatus()
		if err != nil {
			return errors.Wrap(err, "failed to get audit status")
		}
		logging.GetLogger().Info().Str("status", fmt.Sprintf("%v", status)).Msg("received audit status")

		if status.Enabled == 0 {
			logging.GetLogger().Info().Msg("enabling auditing in the kernel")
			if err = client.SetEnabled(true, libaudit.WaitForReply); err != nil {
				return errors.Wrap(err, "failed to set enabled=true")
			}
		}

		if status.RateLimit != uint32(*rate) {
			logging.GetLogger().Info().Uint("rate", *rate).Msg("setting rate limit in kernel")
			if err = client.SetRateLimit(uint32(*rate), libaudit.NoWait); err != nil {
				return errors.Wrap(err, "failed to set rate limit to unlimited")
			}
		}

		if status.BacklogLimit != uint32(*backlog) {
			logging.GetLogger().Info().Uint("backlog", *backlog).Msg("setting backlog limit in kernel")
			if err = client.SetBacklogLimit(uint32(*backlog), libaudit.NoWait); err != nil {
				return errors.Wrap(err, "failed to set backlog limit")
			}
		}

		if status.Enabled != 2 {
			logging.GetLogger().Info().Msg("setting kernel settings as immutable")
			if err = client.SetImmutable(libaudit.NoWait); err != nil {
				return errors.Wrap(err, "failed to set kernel as immutable")
			}
		}

		logging.GetLogger().Info().Int("pid", os.Getpid()).Msg("sending message to kernel registering our PID as the audit daemon")
		if err = client.SetPID(libaudit.NoWait); err != nil {
			return errors.Wrap(err, "failed to set audit PID")
		}
	}

	return receive(client)
}

func receive(r *libaudit.AuditClient) error {
	var err error
	rp := Reporter{}
	rp.uuidGenerator, err = uuid.NewGenerator()
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("uuid.NewGenerator fail")
		return err
	}

	rp.cli, err = eventcenter_helper.NewClientFromEnv()
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("eventcenter_helper.NewClientFromEnv fail")
		return err
	}

	for {
		rawEvent, err := r.Receive(false)
		logging.GetLogger().Info().Str("raw event", fmt.Sprintf("%s", rawEvent)).Msg("Received")
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Receive failed")
			continue
		}

		if rawEvent.Type < auparse.AUDIT_USER_AUTH ||
			rawEvent.Type > auparse.AUDIT_LAST_USER_MSG2 {
			continue
		}

		parsedAuditEntry, err := auparse.Parse(rawEvent.Type, string(rawEvent.Data))
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Failed to parse audit log line")
			continue
		}
		data, err := parsedAuditEntry.Data()
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("Failed to get parsed data")
			continue
		}
		logging.GetLogger().Info().Str("message", fmt.Sprintf("%+v", data)).Msg("Received")
		if parsedAuditEntry.RecordType == auparse.AUDIT_SECCOMP {
			seccompAuditLogEntry := model.SeccompAuditLogEntry{}
			seccompAuditLogEntry.Timestamp = parsedAuditEntry.Timestamp
			val, ok := data["sig"]
			if ok {
				if val == "0" {
					seccompAuditLogEntry.Action = string(model.SecurityModeDetection)
				} else if val == "31" {
					seccompAuditLogEntry.Action = string(model.SecurityModePrevention)
				} else {
					logging.GetLogger().Warn().Str("seccompLogEntry", parsedAuditEntry.RawData).Msg("Unknown seccomp event type")
				}
			}
			val, ok = data["pid"]
			if ok {
				pid, err := strconv.Atoi(val)
				if err != nil {
					logging.GetLogger().Error().Err(err).Str("pid", val).Msg("Not a valid pid")
				} else {
					seccompAuditLogEntry.Pid = pid
				}
			}
			val, ok = data["syscall"]
			if ok {
				syscall, err := strconv.Atoi(val)
				if err != nil {
					logging.GetLogger().Error().Err(err).Str("syscall", val).Msg("Not a valid syscall")
				} else {
					seccompAuditLogEntry.Syscall = syscall
				}
				cmd := exec.Command("auparse", val)
				stderr := &bytes.Buffer{}
				cmd.Stderr = stderr
				out, err := cmd.Output()
				logging.GetLogger().Info().Str("out", string(out)).Str("stderr", fmt.Sprintf("%v\n", stderr)).Msg("Getting syscall name")
				if err != nil {
					logging.GetLogger().Error().Err(err).Str("syscall", val).Msg("Failed to get syscall name")
				} else {
					seccompAuditLogEntry.SyscallName = strings.TrimSpace(string(out))
				}
			}
			logging.GetLogger().Info().Str("event", fmt.Sprintf("%+v", seccompAuditLogEntry)).Msg("Received new event")

			podID, err := getPodIDFromPid(seccompAuditLogEntry.Pid)

			if err != nil {
				logging.GetLogger().Error().Str("alert context", fmt.Sprintf("%+v", err)).Msg("fail!")
				continue
			}
			go alert.NotifyEventWithRetry(rp.cli, alert.GenerateEvent(rp.uuidGenerator, &alert.EventArg{
				Cluster:     "default",
				PodName:     podID,
				PodUID:      podID,
				ContainerID: "containIDtest",
				ProfileName: "test",
				Syscall:     seccompAuditLogEntry.SyscallName,
				Action:      seccompAuditLogEntry.Action,
			}, "seccomp"))
		} else if parsedAuditEntry.RecordType == auparse.AUDIT_AVC {
			val, ok := data["apparmor"]
			if ok && (val == "DENIED" || val == "ALLOWED") {
				apparmorAuditLogEntry := model.ApparmorAuditLogEntry{}
				apparmorAuditLogEntry.Timestamp = parsedAuditEntry.Timestamp
				if val == "DENIED" {
					apparmorAuditLogEntry.Action = string(model.SecurityModePrevention)
				} else if val == "ALLOWED" {
					apparmorAuditLogEntry.Action = string(model.SecurityModeDetection)
				}
				val, ok := data["profile"]
				if ok {
					apparmorAuditLogEntry.Profile = val
				}
				val, ok = data["operation"]
				if ok {
					apparmorAuditLogEntry.Operation = val
				}
				val, ok = data["name"]
				if ok {
					apparmorAuditLogEntry.Name = val
				}
				val, ok = data["requested_mask"]
				if ok {
					apparmorAuditLogEntry.RequestedFlag = val
				}
				val, ok = data["pid"]
				if ok {
					pid, err := strconv.Atoi(val)
					if err != nil {
						logging.GetLogger().Error().Err(err).Str("pid", val).Msg("Not a valid pid")
					} else {
						apparmorAuditLogEntry.Pid = pid
					}
				}
				logging.GetLogger().Info().Str("event", fmt.Sprintf("%+v", apparmorAuditLogEntry)).Msg("Received new event")

				podID, err := getPodIDFromPid(apparmorAuditLogEntry.Pid)

				if err != nil {
					logging.GetLogger().Error().Str("alert context", fmt.Sprintf("%+v", err)).Msg("fail!")
					continue
				}

				go alert.NotifyEventWithRetry(rp.cli, alert.GenerateEvent(rp.uuidGenerator, &alert.EventArg{
					Cluster:     "default",
					PodName:     "test",
					PodUID:      podID,
					ContainerID: "containIDtest",
					Filepath:    apparmorAuditLogEntry.Name,
					ProfileName: apparmorAuditLogEntry.Profile,
					Action:      apparmorAuditLogEntry.Action,
					Pid:         fmt.Sprintf("%d", apparmorAuditLogEntry.Pid),
				}, "apparmor"))
			}
		}
	}
}

func getPodIDFromPid(pid int) (string, error) {
	procPath := fmt.Sprintf(mountInfoPathTemplate, pid)
	fp, err := os.OpenFile(procPath, os.O_RDONLY, 0444)
	if err != nil {
		return "", err
	}
	defer fp.Close()
	podID := ""
	buf := bufio.NewReader(fp)

	for {
		line, _, err := buf.ReadLine()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		infoList := strings.Split(string(line), "/")
		for index, s := range infoList {
			if s == "kubelet" {
				fmt.Println(index)
				podID = infoList[index+2]
				break
			}
		}
	}

	if len(podID) <= 0 {
		err = fmt.Errorf("can't find pod id from pid: %d", pid)
	}
	return podID, err
}
