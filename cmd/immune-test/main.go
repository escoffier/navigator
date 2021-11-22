package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/avast/retry-go"
	log "github.com/sirupsen/logrus"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/piccolo_su/vegeta/pkg/uuid"
	"gitlab.com/security-rd/go-pkg/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
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
	cli            pb.EventsCenterCollectionServiceClient
	uuidGenerator  *uuid.Generator
	clusterManager *k8s.ClusterInfoManager
	psql           *rdbtools.GormWrapper

	pid       = os.Getpid()
	namespace = "default"
	podName   = "immune-test-xak8Khz"
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

	namespace = util.GetEnvWithDefault(namespaceEnv, defaultNamespace)
	podName = util.GetEnvWithDefault(podNameEnv, defaultPodName)
	rdbUser := os.Getenv("RDB_USER")
	rdbPassword := os.Getenv("RDB_PASSWORD")
	rdbHost := os.Getenv("RDB_HOST")
	rdbPort := os.Getenv("RDB_PORT")
	rdbDBName := os.Getenv("RDB_DBNAME")
	rdbSSLMode := os.Getenv("RDB_SSLMODE")
	if rdbUser == "" || rdbPassword == "" || rdbHost == "" || rdbPort == "" || rdbSSLMode == "" || rdbDBName == "" {
		log.Fatal(errors.New("missing rdb envs"))
	}

	pgDSN := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s", rdbUser, rdbPassword, rdbHost, rdbPort, rdbDBName, rdbSSLMode)
	psql, err = rdbtools.GormWrapperOpen(1*time.Second, func() (*gorm.DB, error) {
		db, err := gorm.Open(postgres.Open(pgDSN), &gorm.Config{Logger: logger.Discard.LogMode(logger.Silent)})
		if err != nil {
			logging.GetLogger().Error().Msg(fmt.Sprintf("postgresDB client init error :%s ", err))
			return nil, err
		}
		sqlDB, err := db.DB()
		if err == nil {
			sqlDB.SetMaxOpenConns(30)
			sqlDB.SetMaxIdleConns(5)
			sqlDB.SetConnMaxLifetime(time.Hour)
		}
		return db, nil
	})
	if err != nil {
		log.Fatal(errors.New("missing rdb envs"))
	}

	clusterManager = k8s.NewClusterInfoManager(util.GetEnvWithDefault(clusterManagerURL, ""))

	cli = pb.NewEventsCenterCollectionServiceClient(conn)
	http.HandleFunc("/fileReadWrite", mockFileRW)
	http.HandleFunc("/cmdlineExec", mockCmdLineExec)
	http.HandleFunc("/binaryExec", mockBinaryExec)
	http.HandleFunc("/syscalls", mockSyscalls)
	if err := http.ListenAndServe(util.GetEnvWithDefault(httpAddrEnv, defaultHttpAddr), nil); err != nil {
		log.Fatal(err)
	}
}

const (
	timeout = time.Second * 30
)

func queryResourcePolicyStatus(ctx context.Context, clusterKey string, policyKind model.PolicyKind) ([]*model.ImmunePolicy, error) {
	tctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var resourceUUID uint32
	util.RetryWithBackoff(tctx, func() error {
		q := dal.ResourcesQuery().WithCluster(clusterKey).WithColumnQuery("name", "immune-test")
		if namespace != "default" {
			q = q.WithNamespace(namespace)
		}
		resources, err := dal.GetResources(ctx, psql.Get(), q, 0, 10)
		if err != nil {
			return err
		}
		for _, r := range resources {
			if strings.Contains(r.Name, "immune-test") {
				resourceUUID = r.ID
				break
			}
		}
		return nil
	})
	fmt.Println("res_uuid:", resourceUUID)
	var policies []*model.ImmunePolicy
	err := util.RetryWithBackoff(tctx, func() error {
		var err error
		policies, err = dal.ListImmunePolicies(ctx, psql.Get(),
			dal.NewImmunePoliciesQuery().WithClusterKey(clusterKey).WithKinds([]model.PolicyKind{policyKind}).WithResourceUUID(resourceUUID).WithStatuses([]model.PolicyStatus{model.StatusEnable}),
			0,
			10,
		)
		return err
	}, retry.Attempts(3))

	if err != nil {
		// TODO rm
		fmt.Println("get policies err: ", err)
		return nil, err
	}

	return policies, nil
}

func checkSyscall(ctx context.Context, clusterKey string, syscall string) (bool, int64) {
	policies, err := queryResourcePolicyStatus(ctx, clusterKey, model.PolicyKindSyscalls)
	if err != nil {
		return false, 0
	}
	if len(policies) == 0 {
		return true, 0
	}

	var policyID int64
	for _, policy := range policies {
		policyID = policy.ID
		hit, toContinue := func() (bool, bool) {
			tctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()

			var profiles []*model.ImmuneProfile
			err := util.RetryWithBackoff(tctx, func() error {
				var oneErr error
				profiles, oneErr = dal.GetProfilesOfPolicy(ctx, psql.Get(), policy.ID, "immune-test")
				return oneErr
			}, retry.Attempts(3))

			if err != nil {
				// TODO rm
				fmt.Println("get profiles err: ", err)
				return false, false
			}

			for _, p := range profiles {
				syscallVal := string(p.Value)
				if syscall == syscallVal {
					return true, false
				}
			}
			return false, true
		}()
		if hit {
			return true, policyID
		}
		if !toContinue {
			break
		}
	}
	return false, policyID
}

// returns whether in profile & policyID
func checkBinaryExec(ctx context.Context, clusterKey string) (bool, int64) {
	policies, err := queryResourcePolicyStatus(ctx, clusterKey, model.PolicyKindBinaryExec)
	if err != nil {
		return false, 0
	}
	if len(policies) == 0 {
		return true, 0
	}
	return false, policies[0].ID
}

// returns whether in profile & policyID
func checkCmdExec(ctx context.Context, clusterKey string, cmd string, env string) (bool, int64) {
	policies, err := queryResourcePolicyStatus(ctx, clusterKey, model.PolicyKindCmdExec)
	if err != nil {
		return false, 0
	}
	if len(policies) == 0 {
		return true, 0
	}
	var policyID int64
	for _, policy := range policies {
		policyID = policy.ID
		hit, toContinue := func() (bool, bool) {
			tctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()

			var profiles []*model.ImmuneProfile
			err := util.RetryWithBackoff(tctx, func() error {
				var oneErr error
				profiles, oneErr = dal.GetProfilesOfPolicy(ctx, psql.Get(), policy.ID, "immune-test")
				return oneErr
			}, retry.Attempts(3))

			if err != nil {
				// TODO rm
				fmt.Println("get profiles err: ", err)

				return false, false
			}

			for _, p := range profiles {
				var elem model.CmdExecElement
				err := json.Unmarshal(p.Value, &elem)
				if err != nil {
					// TODO rm
					fmt.Println("json unmarshal error: ", err, "data: ", string(p.Value))
					continue
				}
				if cmd == elem.CommandLine && env == elem.Env {
					return true, false
				}
			}
			return false, true
		}()
		if hit {
			return true, policyID
		}
		if !toContinue {
			break
		}
	}
	return false, policyID
}
func checkFileRW(ctx context.Context, clusterKey string, path string, rw string) (bool, int64) {
	policies, err := queryResourcePolicyStatus(ctx, clusterKey, model.PolicyKindFileRW)
	if err != nil {
		return false, 0
	}
	if len(policies) == 0 {
		return true, 0
	}
	var policyID int64
	for _, policy := range policies {
		policyID = policy.ID
		hit, toContinue := func() (bool, bool) {
			tctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()

			var profiles []*model.ImmuneProfile
			err := util.RetryWithBackoff(tctx, func() error {
				var oneErr error
				profiles, oneErr = dal.GetProfilesOfPolicy(ctx, psql.Get(), policy.ID, "immune-test")
				return oneErr
			}, retry.Attempts(3))

			if err != nil {
				// TODO rm
				fmt.Println("get profiles err: ", err)
				return false, false
			}

			for _, p := range profiles {
				var fileRWVal model.FRWElement
				err := json.Unmarshal(p.Value, &fileRWVal)
				if err != nil {
					// TODO rm
					fmt.Println("json unmarshal error: ", err, "data: ", string(p.Value))
					continue
				}
				if path == fileRWVal.FilePath && rw == fileRWVal.RW {
					return true, false
				}
			}
			return false, true
		}()
		if hit {
			return true, policyID
		}
		if !toContinue {
			break
		}
	}
	return false, policyID
}

func mockFileRW(_ http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	path := r.URL.Query().Get("path")
	if path == "" {
		path = "/tdata/2.txt"
	}
	rw := r.URL.Query().Get("rw")
	if rw == "" {
		rw = "w"
	}
	if rw == "w" {
		f, err := os.Create(path)
		if err == nil {
			defer f.Close()
			f.WriteString(strconv.FormatInt(time.Now().Unix(), 10))
		} else {
			log.Errorf("create file error", err)
		}
	}

	clusterKey, _ := clusterManager.ClusterKey()
	notToSend, policyID := checkFileRW(ctx, clusterKey, path, rw)
	if notToSend {
		return
	}
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
						"en": {Key: "PolicyName", Value: fmt.Sprintf("FileRWPolicy-%d", policyID)},
						"zh": {Key: "策略", Value: fmt.Sprintf("FileRWPolicy-%d", policyID)},
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
							Value: "预警",
						},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {Key: "filePath", Value: path},
						"zh": {Key: "文件路径", Value: path},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {Key: "Read or Write", Value: rw},
						"zh": {Key: "读/写", Value: rw},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {Key: "pid", Value: strconv.Itoa(pid)},
						"zh": {Key: "进程号", Value: strconv.Itoa(pid)},
					},
				},
			},
		},
	}

	if err := sendEvents(ctx, req); err != nil {
		log.Errorf("send events fail, err:%s", err)
	}
}

func mockCmdLineExec(_ http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := r.URL.Query().Get("cmd")
	if cmd == "" {
		cmd = "/bin/cat /tdata/1.txt"
	}
	splits := strings.Split(cmd, " ")
	cmdExec := exec.Command(splits[0], splits[1:]...)
	stdout, err := cmdExec.Output()
	if err != nil {
		log.Errorf("execute %s error: %v", cmd, err)
	} else {
		log.Infof("execute %s success: %s", cmd, string(stdout))
	}

	handleCmdExec(ctx, cmd)
	handleBinaryExec(ctx, splits[0])
}

func handleCmdExec(ctx context.Context, cmd string) {
	clusterKey, _ := clusterManager.ClusterKey()
	notToSend, policyID := checkCmdExec(ctx, clusterKey, cmd, "")
	if notToSend {
		return
	}
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
							Value: cmd,
						},
						"zh": {
							Key:   "命令",
							Value: cmd,
						},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {Key: "PolicyName", Value: fmt.Sprintf("CmdExec-%d", policyID)},
						"zh": {Key: "策略", Value: fmt.Sprintf("CmdExec-%d", policyID)},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {
							Key:   "reason",
							Value: "CommandNotInProfile",
						},
						"zh": {
							Key:   "原因",
							Value: "命令不在模型中",
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
							Value: "预警",
						},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {Key: "pid", Value: strconv.Itoa(pid)},
						"zh": {Key: "进程", Value: strconv.Itoa(pid)},
					},
				},
			},
		},
	}

	if err := sendEvents(ctx, req); err != nil {
		log.Errorf("send events fail, err:%s", err)
	}
}

func handleBinaryExec(ctx context.Context, binary string) {
	clusterKey, _ := clusterManager.ClusterKey()
	notToSend, policyID := checkBinaryExec(ctx, clusterKey)
	if notToSend {
		return
	}
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
							Key:   "binary",
							Value: binary,
						},
						"zh": {
							Key:   "binary",
							Value: binary,
						},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {Key: "PolicyName", Value: fmt.Sprintf("BinaryExec-%d", policyID)},
						"zh": {Key: "策略", Value: fmt.Sprintf("BinaryExec-%d", policyID)},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {
							Key:   "reason",
							Value: "CommandNotInProfile",
						},
						"zh": {
							Key:   "原因",
							Value: "命令不在模型中",
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
						"en": {Key: "pid", Value: strconv.Itoa(pid)},
						"zh": {Key: "进程", Value: strconv.Itoa(pid)},
					},
				},
			},
		},
	}

	if err := sendEvents(ctx, req); err != nil {
		log.Errorf("send events fail, err:%s", err)
	}
}
func mockBinaryExec(_ http.ResponseWriter, _ *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := "/bin/cat /tdata/1.txt"
	splits := strings.Split(cmd, " ")
	cmdExec := exec.Command(splits[0], splits[1:]...)
	stdout, err := cmdExec.Output()
	if err != nil {
		log.Errorf("execute %s error: %v", cmd, err)
	} else {
		log.Infof("execute %s success: %s", cmd, string(stdout))
	}

	handleBinaryExec(ctx, "/bin/cat")
	handleCmdExec(ctx, cmd)
}

func mockSyscalls(_ http.ResponseWriter, _ *http.Request) {

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	_ = os.Getppid()

	clusterKey, _ := clusterManager.ClusterKey()
	notToSend, policyID := checkSyscall(ctx, clusterKey, "getppid")
	if notToSend {
		return
	}
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
						"en": {Key: "policyName", Value: fmt.Sprintf("syscalls-%d", policyID)},
						"zh": {Key: "策略", Value: fmt.Sprintf("syscalls-%d", policyID)},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {Key: "syscall", Value: "getppid"},
						"zh": {Key: "系统调用", Value: "getppid"},
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
							Value: "预警",
						},
					},
				},
				{
					KVHash: map[string]*pb.KV{
						"en": {Key: "pid", Value: strconv.Itoa(pid)},
						"zh": {Key: "进程号", Value: strconv.Itoa(pid)},
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
	send := func() error {
		_, err := cli.SendNotification(ctx, req)
		return err
	}
	return util.RetryWithBackoff(ctx, send)
}
