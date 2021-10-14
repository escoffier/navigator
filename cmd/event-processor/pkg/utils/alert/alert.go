package alert

import (
	"context"
	"fmt"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"gitlab.com/tensorsecurity-rd/go-pkg/pb"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/uuid"
)

type EventArg struct {
	Cluster     string
	Namespace   string
	PodName     string
	PodUID      string
	RuleName    string
	ContainerID string
	Output      string
}

func GenerateEvent(uuidGenerator *uuid.Generator, arg *EventArg, category model.AlertKind) *pb.SendNotificationReq {
	syscall, err := model.GetInfoFromOutput("syscall_name=", arg.Output)
	if err != nil {
		syscall = ""
	}

	user, err := model.GetInfoFromOutput("user=", arg.Output)
	if err != nil {
		user = ""
	}

	command, err := model.GetInfoFromOutput("proc_cmdline=", arg.Output)
	if err != nil {
		command = ""
	}

	pid, err := model.GetInfoFromOutput("proc_pid=", arg.Output)
	if err != nil {
		pid = ""
	}

	ppid, err := model.GetInfoFromOutput("proc_ppid=", arg.Output)
	if err != nil {
		ppid = ""
	}

	procPname, err := model.GetInfoFromOutput("proc_name=", arg.Output)
	if err == nil {
		if len(ppid) > 0 {
			procPname = procPname + fmt.Sprintf("(%s)", ppid)
		}
	} else {
		procPname = ""
	}

	procName := ""
	if command != "" {
		procName = strings.Split(command, " ")[0] + fmt.Sprintf("(%s)", pid)
	}

	req := &pb.SendNotificationReq{
		RuleKey: &pb.RuleKey{
			Module:   model.AlertModuleContainerSecurity,
			Category: string(category),
			Name:     arg.RuleName,
		},
		NotifyContext: &pb.Context{
			Cluster:   arg.Cluster,
			PodName:   arg.PodName,
			Namespace: arg.Namespace,
			CustomKV: []*pb.MultiLanguageKV{
				{
					KVHash: map[string]*pb.KV{
						"en": {Key: "containerId", Value: arg.ContainerID},
						"zh": {Key: "容器id", Value: arg.ContainerID},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {Key: "syscall", Value: syscall},
						"zh": {Key: "系统调用", Value: syscall},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {Key: "user", Value: user},
						"zh": {Key: "用户", Value: user},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {Key: "pid", Value: pid},
						"zh": {Key: "进程号", Value: pid},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {Key: "ppid", Value: ppid},
						"zh": {Key: "父进程号", Value: ppid},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {Key: "procName", Value: procName},
						"zh": {Key: "执行进程", Value: procName},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {Key: "procPname", Value: procPname},
						"zh": {Key: "父进程", Value: procPname},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {Key: "command", Value: command},
						"zh": {Key: "命令", Value: command},
					},
				},
			},
		},
		Timestamp: time.Now().Unix(),
		UUID:      uuidGenerator.GenerateUUID(),
	}

	return req
}

func NotifyEventWithRetry(cli pb.EventsCenterCollectionServiceClient, req *pb.SendNotificationReq) {
	log.Debugf("NotifyEventWithRetry req:%s", req)
	var err error
	var retryDelay = time.Millisecond * 200
	var maxRetryDelay = time.Second * 3
	var maxRetryCount = 10
	var retryCount int
	for {
		err = NotifyEvent(cli, req)
		if err == nil {
			break
		}

		log.Errorf("notifyEvent fail, err:%s", err.Error())
		if retryCount > maxRetryCount {
			log.Errorf("notifyEvent exceed maxRetryCount, retryCount:%d", retryCount)
			return
		}

		time.Sleep(retryDelay)
		retryDelay *= 2
		retryCount++
		if retryDelay > maxRetryDelay {
			retryDelay = maxRetryDelay
		}
	}
}

func NotifyEvent(cli pb.EventsCenterCollectionServiceClient, req *pb.SendNotificationReq) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	_, err := cli.SendNotification(ctx, req)
	return err
}
