package consumer

import (
	"C"
	"fmt"
	eventcenter_helper "gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/utils/eventcenter-helper"
	"gitlab.com/piccolo_su/vegeta/pkg/pb"
	"gitlab.com/piccolo_su/vegeta/pkg/uuid"
	"os"
	"reflect"
	"runtime/debug"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/patrickmn/go-cache"
	log "github.com/sirupsen/logrus"
	"gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/constant"
	"gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/utils"
	"gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/utils/alert"
	ch "gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/utils/container-helper"
	kh "gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/utils/kubernetes-helper"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

type SeccompPrevent struct {
	dataChan              chan constant.Data
	quitChan              chan struct{}
	seccompGeneratorAddr  string
	consoleAddr           string
	cache                 *cache.Cache
	k8sCache              *cache.Cache
	podSyscallsMapPrevent sync.Map
	podSyscallsMapDetect  sync.Map
	ecCli                 pb.EventsCenterCollectionServiceClient
	uuidGenerator         *uuid.Generator
	cu                    ch.ContainerUtil
	ku                    kh.KubernetesUtil
	kubeStop              chan struct{}
}

func (cc *SeccompPrevent) Init(dataChan chan constant.Data) error {
	var err error
	cc.dataChan = dataChan
	cc.quitChan = make(chan struct{}, 1)
	cc.cache = cache.New(10*time.Second, 5*time.Minute)
	cc.k8sCache = cache.New(cache.NoExpiration, 5*time.Minute)

	consoleHost := os.Getenv("TENSORSEC_CONSOLE_HOST")
	if consoleHost == "" {
		return fmt.Errorf("TENSORSEC_CONSOLE_HOST value not set")
	}
	consolePort := os.Getenv("TENSORSEC_CONSOLE_PORT")
	if consolePort == "" {
		return fmt.Errorf("TENSORSEC_CONSOLE_PORT value not set")
	}
	cc.consoleAddr = fmt.Sprintf("http://%s:%s", consoleHost, consolePort)

	myNamespace := os.Getenv("MY_POD_NAMESPACE")
	if myNamespace == "" {
		return fmt.Errorf("MY_POD_NAMESPACE value not set")
	}

	cc.ecCli, err = eventcenter_helper.NewClientFromEnv()
	if err != nil {
		log.Errorf("eventcenter_helper.NewClientFromEnv fail, err:%s", err.Error())
		return err
	}

	cc.uuidGenerator, err = uuid.NewGenerator()
	if err != nil {
		log.Errorf("uuid.NewGenerator fail, err:%s", err.Error())
		return err
	}
	cc.podSyscallsMapPrevent = sync.Map{}
	cc.podSyscallsMapDetect = sync.Map{}
	cc.cu = ch.NewContainerUtil()
	cc.ku = kh.NewKubernetesUtil()
	kubeStop, err := kh.InitKubernetesWatcher(cc.k8sCache, &cc.podSyscallsMapPrevent, &cc.podSyscallsMapDetect, myNamespace)
	if err != nil {
		return err
	}
	cc.kubeStop = kubeStop
	return nil
}

func (cc *SeccompPrevent) processSyscall(event *constant.TotalData, testingPhase bool) error {
	ExtraInfo := make(map[string]interface{})
	if event.IsSyscall {
		syscall := C.GoString((*C.char)(unsafe.Pointer(&event.EventInfo.EventName)))
		if syscall == "exit" {
			return nil
		} // TensorDig generates EXIT, yet EXIT is not specified
		ExtraInfo["syscall"] = syscall
		prefix := syscall + "__"
		elements := reflect.ValueOf(event).Elem()
		types := elements.Type()
		for i := 0; i < elements.NumField(); i++ {
			field := elements.Field(i)
			name := types.Field(i).Tag.Get("json")
			if strings.HasPrefix(name, prefix) {
				ExtraInfo[name] = field.Interface()
			}
		}
	}
	s := ExtraInfo["syscall"].(string)
	if s == "socket" || s == "open" || s == "openat" || s == "execve" || s == "dup2" {
		return nil
	}
	pid := int(event.EventInfo.Pid)
	ptid := int(event.EventInfo.Ptgid)
	containerPID, err := cc.cu.GetContainerPid(pid)
	if err != nil {
		log.Debugf("Problem getting container ID: %w", err)
		log.Debugf("Checking if parent %d of %d still has docker context\n", pid, ptid)
		containerPID, err = cc.cu.GetContainerPid(ptid)
		if err != nil {
			log.Debugf("Problem getting container ID: %w", err)
			return err
		}
	}
	if containerPID == 1 || pid <= 0 {
		log.Debugf("Host process: %d", pid)
		return fmt.Errorf("Host process: %d", pid)
	}
	info, err := cc.ku.LookupPod(cc.k8sCache, containerPID, pid, ExtraInfo["syscall"].(string))
	if err != nil || info.PodName == "" {
		log.Debugf("Problem getting pod ID: %w", err)
		log.Debugf("Checking if parent %d of %d still has pod context\n", ptid, pid)
		info, err = cc.ku.LookupPod(cc.k8sCache, containerPID, ptid, ExtraInfo["syscall"].(string))
		if err != nil {
			log.Debugf("Problem getting pod ID: %w", err)
			return err
		}
	}
	if info.PodName != "" {
		x, found := cc.k8sCache.Get(info.ContainerID)
		kubeInfo := x.(*kh.KubeSelectedInfo)
		if found {
			podSyscalls, ok := cc.podSyscallsMapPrevent.Load(kubeInfo.SeccompProfileName)
			if !ok {
				log.Debugf("Prevent profile not in syscall cache map")
			} else {
				found := Find(podSyscalls.([]string), strings.ToLower(info.Syscall))
				if !found {
					log.Infof("Syscall %s found that should be blocked by seccomp profile %s", strings.ToLower(info.Syscall), kubeInfo.SeccompProfileName)
					go alert.NotifyEventWithRetry(cc.ecCli, alert.GenerateSeccompEvent(cc.uuidGenerator, &alert.SeccompEventArg{
						Cluster:     "default",
						PodName:     info.PodName,
						PodUID:      kubeInfo.PodUID,
						ContainerID: kubeInfo.ContainerID,
						ProfileName: kubeInfo.SeccompProfileName,
						Syscall:     strings.ToLower(info.Syscall),
						Phase:       "PROD",
						Action:      kubeInfo.SeccompProfileMode,
					}))
				}
				return nil
			}
			podSyscalls, ok = cc.podSyscallsMapDetect.Load(kubeInfo.SeccompProfileName)
			if !ok {
				log.Debugf("Detect profile not in syscall cache map")
			} else {
				found := Find(podSyscalls.([]string), strings.ToLower(info.Syscall))
				if !found {
					log.Infof("Syscall %s found that should be detected by seccomp profile %s", strings.ToLower(info.Syscall), kubeInfo.SeccompProfileName)
					go alert.NotifyEventWithRetry(cc.ecCli, alert.GenerateSeccompEvent(cc.uuidGenerator, &alert.SeccompEventArg{
						Cluster:     "default",
						PodName:     info.PodName,
						PodUID:      kubeInfo.PodUID,
						ContainerID: kubeInfo.ContainerID,
						ProfileName: kubeInfo.SeccompProfileName,
						Syscall:     strings.ToLower(info.Syscall),
						Phase:       "PROD",
						Action:      kubeInfo.SeccompProfileMode,
					}))
				}
			}
		} else {
			return fmt.Errorf("Container not found in cache")
		}
	}
	return nil
}

func (cc *SeccompPrevent) Consume(_ *utils.NsMap) {
	for data := range cc.dataChan {
		switch event := data.(type) {
		case *constant.TotalData:
			go func(event *constant.TotalData) {
				defer func() {
					if r := recover(); r != nil {
						logging.GetLogger().Error().Msgf("Panic : %v. stack: %s", r, debug.Stack())
					}
				}()

				err := cc.processSyscall(event, true)
				if err != nil {
					time.AfterFunc(10*time.Second, func() { cc.processSyscall(event, true) })
				}
			}(event)
		default:
			log.Warn("SeccompPrevent data type should be one of listed type.")
		}
	}
	cc.kubeStop <- struct{}{}
	cc.quitChan <- struct{}{}
	log.Info("Ending customer")
}

func Find(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

func (cc *SeccompPrevent) Stop() {
	<-cc.quitChan
}

func NewSeccompPrevent() *SeccompPrevent {
	return &SeccompPrevent{}
}
