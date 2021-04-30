package consumer

import (
	"C"
	"bytes"
	"encoding/json"
	"fmt"
	eventcenter_helper "gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/utils/eventcenter-helper"
	"gitlab.com/piccolo_su/vegeta/pkg/pb"
	"gitlab.com/piccolo_su/vegeta/pkg/uuid"
	"net/http"
	"os"
	"reflect"
	"runtime/debug"
	"strconv"
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

type SeccompGeneration struct {
	dataChan                 chan constant.Data
	quitChan                 chan struct{}
	seccompGeneratorAddr     string
	consoleAddr              string
	cache                    *cache.Cache
	k8sCache                 *cache.Cache
	podSyscallsMapPrevent    sync.Map
	podSyscallsMapDetect     sync.Map
	seccompGenerationTimeout int
	client                   *http.Client
	ecCli                    pb.EventsCenterCollectionServiceClient
	uuidGenerator            *uuid.Generator
	cu                       ch.ContainerUtil
	ku                       kh.KubernetesUtil
	kubeStop                 chan struct{}
	startTime                time.Time
	generationUUID           string
}

type SyscallWhitelist struct {
	PodName  string   `json:"pod"`
	Syscalls []string `json:"syscalls"`
	UUID     string   `json:"uuid"`
	Mode     string   `json:"mode"`
}

func (cc *SeccompGeneration) Init(dataChan chan constant.Data) error {
	var err error
	cc.dataChan = dataChan
	cc.quitChan = make(chan struct{}, 1)
	cc.cache = cache.New(10*time.Second, 5*time.Minute)
	cc.k8sCache = cache.New(cache.NoExpiration, 5*time.Minute)

	seccompGeneratorHost := os.Getenv("TENSORSEC_SECCOMP_GENERATOR_HOST")
	if seccompGeneratorHost == "" {
		return fmt.Errorf("TENSORSEC_SECCOMP_GENERATOR_HOST value not set")
	}
	seccompGeneratorPort := os.Getenv("TENSORSEC_SECCOMP_GENERATOR_PORT")
	if seccompGeneratorPort == "" {
		return fmt.Errorf("TENSORSEC_SECCOMP_GENERATOR_PORT value not set")
	}
	cc.seccompGeneratorAddr = fmt.Sprintf("http://%s:%s", seccompGeneratorHost, seccompGeneratorPort)

	consoleHost := os.Getenv("TENSORSEC_CONSOLE_HOST")
	if consoleHost == "" {
		return fmt.Errorf("TENSORSEC_CONSOLE_HOST value not set")
	}
	consolePort := os.Getenv("TENSORSEC_CONSOLE_PORT")
	if consolePort == "" {
		return fmt.Errorf("TENSORSEC_CONSOLE_PORT value not set")
	}
	cc.consoleAddr = fmt.Sprintf("http://%s:%s", consoleHost, consolePort)

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

	cc.generationUUID = os.Getenv("RANDOM_UUID")

	myNamespace := os.Getenv("MY_POD_NAMESPACE")
	if myNamespace == "" {
		return fmt.Errorf("MY_POD_NAMESPACE value not set")
	}

	cc.client = &http.Client{}
	cc.podSyscallsMapPrevent = sync.Map{}
	cc.podSyscallsMapDetect = sync.Map{}
	testingAfter := os.Getenv("TESTING_AFTER")
	if testingAfter != "" {
		testingAfterInt, err := strconv.Atoi(testingAfter)
		if err != nil {
			return fmt.Errorf("TESTING_AFTER value needs to be and integer (seconds)")
		}
		cc.seccompGenerationTimeout = testingAfterInt
	} else {
		cc.seccompGenerationTimeout = -1
	}
	cc.cu = ch.NewContainerUtil()
	cc.ku = kh.NewKubernetesUtil()
	cc.startTime = time.Now()
	kubeStop, err := kh.InitKubernetesWatcher(cc.k8sCache, &cc.podSyscallsMapPrevent, &cc.podSyscallsMapDetect, myNamespace)
	if err != nil {
		return err
	}
	cc.kubeStop = kubeStop
	return nil
}

func (cc *SeccompGeneration) processSyscall(event *constant.TotalData, testingPhase bool) error {
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
		log.Debugf("Checking if parent %d of %d still has pod context\n", pid, ptid)
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
					if !testingPhase {
						newPodSyscalls := append(podSyscalls.([]string), strings.ToLower(info.Syscall))
						cc.podSyscallsMapPrevent.Store(kubeInfo.SeccompProfileName, newPodSyscalls)
						log.Infof("Successfully added new syscall %s to profile %s", strings.ToLower(info.Syscall), kubeInfo.SeccompProfileName)
					} else {
						log.Infof("New syscall %s found during testing, but not during training in profile %s", strings.ToLower(info.Syscall), kubeInfo.SeccompProfileName)

						go alert.NotifyEventWithRetry(cc.ecCli, alert.GenerateSeccompEvent(cc.uuidGenerator, &alert.SeccompEventArg{
							Cluster:     "default",
							PodName:     info.PodName,
							PodUID:      kubeInfo.PodUID,
							ContainerID: kubeInfo.ContainerID,
							ProfileName: kubeInfo.SeccompProfileName,
							Syscall:     strings.ToLower(info.Syscall),
							Phase:       "TEST",
							Action:      "DETECTION",
						}))
					}
				}
				return nil
			}
			podSyscalls, ok = cc.podSyscallsMapDetect.Load(kubeInfo.SeccompProfileName)
			if !ok {
				log.Debugf("Detect profile not in syscall cache map")
				return fmt.Errorf("Detect profile not in syscall cache map")
			}
			found := Find(podSyscalls.([]string), strings.ToLower(info.Syscall))
			if !found {
				if !testingPhase {
					newPodSyscalls := append(podSyscalls.([]string), strings.ToLower(info.Syscall))
					cc.podSyscallsMapDetect.Store(kubeInfo.SeccompProfileName, newPodSyscalls)
					log.Infof("Successfully added new syscall %s to profile %s", strings.ToLower(info.Syscall), kubeInfo.SeccompProfileName)
				} else {
					log.Infof("New syscall %s found during testing, but not during training in profile %s", strings.ToLower(info.Syscall), kubeInfo.SeccompProfileName)
					go alert.NotifyEventWithRetry(cc.ecCli, alert.GenerateSeccompEvent(cc.uuidGenerator, &alert.SeccompEventArg{
						Cluster:     "default",
						PodName:     info.PodName,
						PodUID:      kubeInfo.PodUID,
						ContainerID: kubeInfo.ContainerID,
						ProfileName: kubeInfo.SeccompProfileName,
						Syscall:     strings.ToLower(info.Syscall),
						Phase:       "TEST",
						Action:      "DETECTION",
					}))
				}
			}
		} else {
			return fmt.Errorf("Container not found in cache")
		}
	}
	return nil
}

func (cc *SeccompGeneration) Consume(_ *utils.NsMap) {
process:
	for data := range cc.dataChan {
		switch event := data.(type) {
		case *constant.TotalData:
			if cc.seccompGenerationTimeout != -1 && time.Now().After(cc.startTime.Add(time.Duration(cc.seccompGenerationTimeout)*time.Second)) {
				break process
			}
			go func(event *constant.TotalData) {
				defer func() {
					if r := recover(); r != nil {
						logging.GetLogger().Error().Msgf("Panic : %v. stack: %s", r, debug.Stack())
					}
				}()

				err := cc.processSyscall(event, false)
				if err != nil {
					time.AfterFunc(10*time.Second, func() { cc.processSyscall(event, false) })
				}
			}(event)
		default:
			log.Warn("SeccompConsumer data type should be one of listed type.")
		}
	}

	log.Info("Sending request to generate prevent seccomp profiles for node's images")
	cc.podSyscallsMapPrevent.Range(func(podName, syscallList interface{}) bool {
		log.Infof("Sending request to generate seccomp profiles for %s", podName.(string))

		syscallWhitelist := SyscallWhitelist{
			PodName:  podName.(string),
			Syscalls: syscallList.([]string),
			UUID:     cc.generationUUID,
			Mode:     "PREVENT",
		}
		jsonStr, err := json.Marshal(syscallWhitelist)
		if err != nil {
			log.Errorf("Failed to marshal syscall whitelist for %s: %w.", podName.(string), err)
			return true
		}
		req, err := http.NewRequest("POST", cc.seccompGeneratorAddr, bytes.NewBuffer(jsonStr))
		if err != nil {
			log.Errorf("NewRequest fail, err:%s", err.Error())
			return true
		}
		req.Header.Set("Content-Type", "application/json")
		_, err = cc.client.Do(req)
		if err != nil {
			log.Errorf("Failed to send info to seccomp generator about %s: %w.", podName.(string), err)
			return true
		}
		return true
	})

	log.Info("Sending request to generate detect seccomp profiles for node's images")
	cc.podSyscallsMapDetect.Range(func(podName, syscallList interface{}) bool {
		log.Infof("Sending request to generate seccomp profiles for %s", podName.(string))

		syscallWhitelist := SyscallWhitelist{
			PodName:  podName.(string),
			Syscalls: syscallList.([]string),
			UUID:     cc.generationUUID,
			Mode:     "DETECT",
		}
		jsonStr, err := json.Marshal(syscallWhitelist)
		if err != nil {
			log.Errorf("Failed to marshal syscall whitelist for %s: %w.", podName.(string), err)
			return true
		}
		req, err := http.NewRequest("POST", cc.seccompGeneratorAddr, bytes.NewBuffer(jsonStr))
		if err != nil {
			log.Errorf("NewRequest fail, err:%s", err.Error())
			return true
		}

		req.Header.Set("Content-Type", "application/json")
		_, err = cc.client.Do(req)
		if err != nil {
			log.Errorf("Failed to send info to seccomp generator about %s: %w.", podName.(string), err)
			return true
		}
		return true
	})

	if cc.seccompGenerationTimeout != -1 {
		log.Infof("Starting testing phase")
		for data := range cc.dataChan {
			switch event := data.(type) {
			case *constant.TotalData:
				go func(event *constant.TotalData) {
					defer func() {
						if r := recover(); r != nil {
							logging.GetLogger().Error().Msgf("error : %v. stack: %s", r, debug.Stack())
						}
					}()

					err := cc.processSyscall(event, true)
					if err != nil {
						time.AfterFunc(10*time.Second, func() { cc.processSyscall(event, true) })
					}
				}(event)
			default:
				log.Warn("SeccompConsumer data type should be one of listed type.")
			}
		}
	} else {
		log.Infof("Skipping testing phase")
	}

	cc.kubeStop <- struct{}{}
	cc.quitChan <- struct{}{}
	log.Info("Ending customer")
}

func (cc *SeccompGeneration) Stop() {
	<-cc.quitChan
}

func NewSeccompGeneration() *SeccompGeneration {
	return &SeccompGeneration{}
}
