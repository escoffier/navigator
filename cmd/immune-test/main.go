package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
	"gitlab.com/security-rd/go-pkg/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/piccolo_su/vegeta/pkg/uuid"
)

const (
	eventGrpcUrlEnv     = "EVENT_GRPC_URL"
	defaultEventGrpcUrl = "eventcenter:9090"
	httpAddrEnv         = "HTTP_ADDR"
	defaultHttpAddr     = ":8080"
	podNameEnv          = "MY_POD_NAME"
	defaultPodName      = "immune-test-xak8Khz"
	podUidEnv           = "MY_POD_UID"
	defaultPodUID       = "aad57431-ec44-4cac-991a-f1c45cc77054"
	namespaceEnv        = "MY_POD_NAMESPACE"
	defaultNamespace    = "idss"
	clusterManagerURL   = "CLUSTER_MANAGER_URL"
	containerIDEnv      = "MY_CONTAINER_ID"
	defaultContainerID  = "3b018a58d88a"
)

var (
	cli           pb.EventsCenterCollectionServiceClient
	uuidGenerator *uuid.Generator
	clusterKey    string
)

func main() {
	conn, err := grpc.Dial(util.GetEnvWithDefault(eventGrpcUrlEnv, defaultEventGrpcUrl),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})))
	if err != nil {
		log.Fatal(err)
	}

	uuidGenerator, err = uuid.NewGenerator()
	if err != nil {
		log.Fatal(err)
	}

	clusterManager := k8s.NewClusterInfoManager(util.GetEnvWithDefault(clusterManagerURL, ""))
	clusterKey, _ = clusterManager.ClusterKey()

	cli = pb.NewEventsCenterCollectionServiceClient(conn)
	http.HandleFunc("/apparmor", mockApparmor)
	http.HandleFunc("/commandWhiteList", mockCommandWhiteList)
	http.HandleFunc("/driftPrevention", mockDriftPrevention)
	http.HandleFunc("/seccomp", mockSeccomp)
	if err := http.ListenAndServe(util.GetEnvWithDefault(httpAddrEnv, defaultHttpAddr), nil); err != nil {
		log.Fatal(err)
	}
}

const (
	timeout = time.Second * 10
)

func mockApparmor(_ http.ResponseWriter, _ *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req := &pb.SendNotificationReq{
		RuleKey: &pb.RuleKey{
			Module:   "ContainerSecurity",
			Category: "apparmor",
			Name:     "apparmor",
		},
		Timestamp: time.Now().Unix(),
		UUID:      uuidGenerator.GenerateUUID(),
		NotifyContext: &pb.Context{
			Cluster:   clusterKey,
			Namespace: util.GetEnvWithDefault(namespaceEnv, defaultNamespace),
			ServiceID: "immute-test",
			PodName:   util.GetEnvWithDefault(podNameEnv, defaultPodName),
			PodUID:    util.GetEnvWithDefault(podUidEnv, defaultPodUID),
			CustomKV: []*pb.MultiLanguageKV{
				{
					KVHash: map[string]*pb.KV{
						"en": {Key: "containerId", Value: util.GetEnvWithDefault(containerIDEnv, defaultContainerID)},
						"zh": {Key: "容器id", Value: util.GetEnvWithDefault(containerIDEnv, defaultContainerID)},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {Key: "profileName", Value: "apparmor-1"},
						"zh": {Key: "名称", Value: "apparmor-1"},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {
							Key:   "action",
							Value: "Notified",
						},
						"zh": {
							Key:   "行为",
							Value: "告警",
						},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {Key: "filePath", Value: "/test.sh"},
						"zh": {Key: "文件路径", Value: "/test.sh"},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {Key: "pid", Value: "2"},
						"zh": {Key: "进程号", Value: "2"},
					},
				},
			},
		},
	}

	if err := sendEvents(ctx, req); err != nil {
		log.Errorf("send events fail, err:%s", err)
	}
}

func mockCommandWhiteList(_ http.ResponseWriter, _ *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req := &pb.SendNotificationReq{
		RuleKey: &pb.RuleKey{
			Module:   "ContainerSecurity",
			Category: "driftPrevention",
			Name:     "driftPrevention",
		},
		Timestamp: time.Now().Unix(),
		UUID:      uuidGenerator.GenerateUUID(),
		NotifyContext: &pb.Context{
			Cluster:   clusterKey,
			Namespace: util.GetEnvWithDefault(namespaceEnv, defaultNamespace),
			ServiceID: "immute-test",
			PodName:   util.GetEnvWithDefault(podNameEnv, defaultPodName),
			PodUID:    util.GetEnvWithDefault(podUidEnv, defaultPodUID),
			CustomKV: []*pb.MultiLanguageKV{
				{
					KVHash: map[string]*pb.KV{
						"en": {
							Key:   "command",
							Value: "/bin/cat /test.sh",
						},
						"zh": {
							Key:   "命令",
							Value: "/bin/cat /test.sh",
						},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {
							Key:   "reason",
							Value: "CommandNotInWhitelist",
						},
						"zh": {
							Key:   "原因",
							Value: "命令不在白名单中",
						},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {
							Key:   "action",
							Value: "Notified",
						},
						"zh": {
							Key:   "行为",
							Value: "告警",
						},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {
							Key:   "syscall",
							Value: "execve",
						},
						"zh": {
							Key:   "系统调用",
							Value: "execve",
						},
					},
				},
			},
		},
	}

	if err := sendEvents(ctx, req); err != nil {
		log.Errorf("send events fail, err:%s", err)
	}
}

func mockDriftPrevention(_ http.ResponseWriter, _ *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req := &pb.SendNotificationReq{
		RuleKey: &pb.RuleKey{
			Module:   "ContainerSecurity",
			Category: "driftPrevention",
			Name:     "driftPrevention",
		},
		Timestamp: time.Now().Unix(),
		UUID:      uuidGenerator.GenerateUUID(),
		NotifyContext: &pb.Context{
			Cluster:   clusterKey,
			Namespace: util.GetEnvWithDefault(namespaceEnv, defaultNamespace),
			ServiceID: "immute-test",
			PodName:   util.GetEnvWithDefault(podNameEnv, defaultPodName),
			PodUID:    util.GetEnvWithDefault(podUidEnv, defaultPodUID),
			CustomKV: []*pb.MultiLanguageKV{
				{
					KVHash: map[string]*pb.KV{
						"en": {
							Key:   "filepath",
							Value: "/test.sh",
						},
						"zh": {
							Key:   "文件路径",
							Value: "/test.sh",
						},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {
							Key:   "reason",
							Value: "CommandNotInWhitelist",
						},
						"zh": {
							Key:   "原因",
							Value: "命令不在白名单中",
						},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {
							Key:   "action",
							Value: "Notified",
						},
						"zh": {
							Key:   "行为",
							Value: "告警",
						},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {
							Key:   "syscall",
							Value: "execve",
						},
						"zh": {
							Key:   "系统调用",
							Value: "execve",
						},
					},
				},
			},
		},
	}

	if err := sendEvents(ctx, req); err != nil {
		log.Errorf("send events fail, err:%s", err)
	}
}

func mockSeccomp(_ http.ResponseWriter, _ *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req := &pb.SendNotificationReq{
		RuleKey: &pb.RuleKey{
			Module:   "ContainerSecurity",
			Category: "seccompProfile",
			Name:     "seccompProfile",
		},
		Timestamp: time.Now().Unix(),
		UUID:      uuidGenerator.GenerateUUID(),
		NotifyContext: &pb.Context{
			Cluster:   clusterKey,
			Namespace: util.GetEnvWithDefault(namespaceEnv, defaultNamespace),
			ServiceID: "immute-test",
			PodName:   util.GetEnvWithDefault(podNameEnv, defaultPodName),
			PodUID:    util.GetEnvWithDefault(podUidEnv, defaultPodUID),
			CustomKV: []*pb.MultiLanguageKV{
				{
					KVHash: map[string]*pb.KV{
						"en": {Key: "containerId", Value: util.GetEnvWithDefault(containerIDEnv, defaultContainerID)},
						"zh": {Key: "容器id", Value: util.GetEnvWithDefault(containerIDEnv, defaultContainerID)},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {Key: "profileName", Value: "seccomp-1"},
						"zh": {Key: "名称", Value: "seccomp-1"},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {Key: "syscall", Value: "execve"},
						"zh": {Key: "系统调用", Value: "execve"},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {
							Key:   "action",
							Value: "Notified",
						},
						"zh": {
							Key:   "行为",
							Value: "告警",
						},
					},
				},
			},
		},
	}

	if err := sendEvents(ctx, req); err != nil {
		log.Errorf("send events fail, err:%s", err)
	}
}

func sendEvents(ctx context.Context, req *pb.SendNotificationReq) error {
	jsonContents, _ := json.Marshal(req)
	log.Infof("request:%s", util.Bytes2StringNoCopy(jsonContents))
	send := func() error {
		_, err := cli.SendNotification(ctx, req)
		return err
	}
	return util.RetryWithBackoff(ctx, send)
}
