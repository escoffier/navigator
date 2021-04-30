package consumer

import (
	"C"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/utils/alert"
	eventcenter_helper "gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/utils/eventcenter-helper"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/pb"
	"gitlab.com/piccolo_su/vegeta/pkg/uuid"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/patrickmn/go-cache"
	"gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/constant"
	"gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/utils"

	ch "gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/utils/container-helper"
	kh "gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/utils/kubernetes-helper"

	log "github.com/sirupsen/logrus"
)

type ReporterConsumer struct {
	uuidGenerator *uuid.Generator
	dataChan      chan constant.Data
	quitChan      chan struct{}
	cli           pb.EventsCenterCollectionServiceClient
	cu            ch.ContainerUtil
	ku            kh.KubernetesUtil
	cache         *cache.Cache
	k8sCache      *cache.Cache
	kubeStop      chan struct{}
}

func (cc *ReporterConsumer) Init(dataChan chan constant.Data) error {
	var err error
	cc.dataChan = dataChan
	cc.quitChan = make(chan struct{}, 1)
	cc.cli, err = eventcenter_helper.NewClientFromEnv()
	if err != nil {
		log.Errorf("eventcenter_helper.NewClientFromEnv fail, err:%s", err.Error())
		return err
	}

	cc.uuidGenerator, err = uuid.NewGenerator()
	if err != nil {
		log.Errorf("uuid.NewGenerator fail, err:%s", err.Error())
		return err
	}

	cc.cu = ch.NewContainerUtil()
	cc.ku = kh.NewKubernetesUtil()
	cc.cache = cache.New(10*time.Second, 5*time.Minute)
	cc.k8sCache = cache.New(cache.NoExpiration, 5*time.Minute)

	myNamespace := os.Getenv("MY_POD_NAMESPACE")
	if myNamespace == "" {
		return fmt.Errorf("MY_POD_NAMESPACE value not set")
	}
	kubeStop, err := kh.InitKubernetesWatcher(cc.k8sCache, nil, nil, myNamespace)
	if err != nil {
		return err
	}
	cc.kubeStop = kubeStop
	return nil
}

func (cc *ReporterConsumer) Consume(_ *utils.NsMap) {
	for data := range cc.dataChan {
		switch event := data.(type) {
		case *constant.TotalData:
			cc.handleEvent(event)
		default:
			log.Warn("ReporterConsumer data type should be one of listed type.")
		}
	}

	cc.kubeStop <- struct{}{}
	cc.quitChan <- struct{}{}
}

func (cc *ReporterConsumer) handleEvent(event *constant.TotalData) {
	pid := int(event.EventInfo.Pid)
	ptid := int(event.EventInfo.Ptgid)
	containerPID, err := cc.cu.GetContainerPid(pid)
	if err != nil {
		log.Debugf("Problem getting container ID: %w", err)
		return
	}

	if containerPID == 1 {
		log.Debugf("Checking if parent %d of %d still has docker context\n", pid, ptid)
		containerPID, err = cc.cu.GetContainerPid(ptid)
		if err != nil {
			log.Debugf("Problem getting container ID: %w", err)
			return
		}
	}

	extraInfo := make(map[string]interface{})
	if event.IsSyscall {
		syscall := C.GoString((*C.char)(unsafe.Pointer(&event.EventInfo.EventName)))
		if syscall == "exit" {
			return
		} // TensorDig generates EXIT, yet EXIT is not specified
		extraInfo["syscall"] = syscall
		prefix := syscall + "__"
		elements := reflect.ValueOf(event).Elem()
		types := elements.Type()
		for i := 0; i < elements.NumField(); i++ {
			field := elements.Field(i)
			name := types.Field(i).Tag.Get("json")
			if strings.HasPrefix(name, prefix) {
				extraInfo[name] = field.Interface()
			}
		}
	}

	if pid > 0 {
		syscall, _ := extraInfo["syscall"].(string)
		info, err := cc.getPodInfo(containerPID, pid, ptid, syscall)
		if err != nil || info.DockerPID <= 0 {
			return
		}

		out := map[string]interface{}{}
		v := reflect.ValueOf(*info)
		typeOfS := v.Type()
		for i := 0; i < v.NumField(); i++ {
			out[typeOfS.Field(i).Name] = v.Field(i).Interface()
		}
		for key, element := range extraInfo {
			out[key] = element
		}
		v = reflect.ValueOf(event.EventInfo)
		typeOfS = v.Type()
		for i := 0; i < v.NumField(); i++ {
			out[typeOfS.Field(i).Name] = v.Field(i).Interface()
		}
		if info.Syscall == "socket" {
			cc.cache.Set(info.ContainerID+" "+strconv.Itoa(pid)+" "+strconv.FormatInt(event.EventInfo.Ret, 10), true, cache.DefaultExpiration)
			// For now AF_INET is only bound to reverse shell with dup2, so we don't want to spam elasticsearch with this data
			if sf, _ := extraInfo["socket__family"].(uint64); sf == 2 {
				if sp, _ := extraInfo["socket__protocol"].(uint64); sp != 132 {
					return
				}
			}
			// Other socket detections are to be sent for alerting
		} else if info.Syscall == "dup2" {
			dof, _ := extraInfo["dup2__oldfd"].(uint64)
			_, found := cc.cache.Get(info.ContainerID + " " + strconv.Itoa(pid) + " " + strconv.FormatUint(dof, 10))
			if found {
				log.Info("Reverse shell attempt with socket/dup2 detected")
				out["reverse_shell_socket_dup2"] = "true"
			} else {
				// If there is no match with a socket fd in the same pod, we don't want to track this dup2 syscall
				return
			}
		}
		log.Infof("out:%v", out)
		if req := cc.generateEventNotifyReq(out); req != nil {
			go alert.NotifyEventWithRetry(cc.cli, req)
		}

	}
}

func (cc *ReporterConsumer) getPodInfo(containerPID, pid, ptid int, syscall string) (*kh.SyscallContext, error) {
	info, err := cc.ku.LookupPod(cc.k8sCache, containerPID, pid, syscall)
	if err != nil {
		log.Debugf("Problem getting pod ID: %s", err.Error())
		return nil, err
	}

	if info.DockerPID <= 0 {
		info, err = cc.ku.LookupPod(cc.k8sCache, containerPID, ptid, syscall)
		if err != nil {
			log.Debugf("Problem getting pod ID: %s", err.Error())
			return nil, err
		}

		if info.DockerPID <= 0 {
			log.Debugf("dockerPid is 0")
		}
	}

	return info, nil
}

func (cc *ReporterConsumer) generateEventNotifyReq(info map[string]interface{}) *pb.SendNotificationReq {
	vulnerability := cc.getVulnerability(info)
	log.Infof("getVulnerability:%s", vulnerability)
	if vulnerability == "" {
		return nil
	}

	podUID, _ := info["PodUID"].(string)
	podName, _ := info["PodName"].(string)
	cluster := "default"
	containerID, _ := info["ContainerID"].(string)

	var req = &pb.SendNotificationReq{
		RuleKey: &pb.RuleKey{Module: model.AlertModuleContainerSecurity, Name: vulnerability},
		NotifyContext: &pb.Context{
			PodUID:  podUID,
			PodName: podName,
			Cluster: cluster,
			CustomKV: []*pb.MultiLanguageKV{
				{
					KVHash: map[string]*pb.KV{
						"en": {Key: "containerId", Value: containerID},
						"zh": {Key: "容器id", Value: containerID},
					},
				},
			},
		},
		UUID:      cc.uuidGenerator.GenerateUUID(),
		Timestamp: time.Now().Unix(),
	}

	if strings.HasPrefix(vulnerability, "CVE") {
		req.RuleKey.Category = string(model.AlertKindVulnerabilityExploitAttack)
	} else {
		req.RuleKey.Category = string(model.AlertKindReverseShellAttack)
		pid, _ := info["Pid"].(float64)
		req.NotifyContext.CustomKV = append(req.NotifyContext.CustomKV, &pb.MultiLanguageKV{
			KVHash: map[string]*pb.KV{
				"en": {Key: "pid", Value: strconv.Itoa(int(pid))},
				"zh": {Key: "进程id", Value: strconv.Itoa(int(pid))},
			},
		})

	}

	return req
}

func (cc *ReporterConsumer) getVulnerability(info map[string]interface{}) string {
	var vulnerability string
	if val, ok := info["socket__protocol"]; ok {
		if _v, _ := val.(uint32); _v == 132 {
			vulnerability = "CVE-2019-3874"
		}
	}
	if val, ok := info["socket__family"]; ok {
		if _v, _ := val.(uint32); _v == 17 {
			vulnerability = "CVE-2020-14386"
		}
	}
	if _, ok := info["reverse_shell_socket_dup2"]; ok {
		vulnerability = "RS-SOCKET_DUP2"
	}
	if _, ok := info["openat__filename"]; ok {
		vulnerability = "CVE-2019-5736"
	}
	if _, ok := info["open__filename"]; ok {
		vulnerability = "CVE-2019-5736"
	}
	if val, ok := info["execve__filename"]; ok {
		if _v, _ := val.(string); _v == "/usr/bin/sudo" {
			vulnerability = "CVE-2019-14287"
		} else if _v == "/bin/nc" || _v == "/usr/bin/ncat" {
			vulnerability = "RS-NC"
		}
	}
	if val, ok := info["exec__filename"]; ok {
		if _v, _ := val.(string); _v == "/usr/bin/sudo" {
			vulnerability = "CVE-2019-14287"
		} else if _v == "/bin/nc" || _v == "/usr/bin/ncat" {
			vulnerability = "RS-NC"
		}
	}

	return vulnerability
}

func (cc *ReporterConsumer) Stop() {
	<-cc.quitChan
}

func NewReporterConsumer() *ReporterConsumer {
	return &ReporterConsumer{}
}
