package consumer

import (
	"C"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/patrickmn/go-cache"
	"gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/constant"
	"gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/utils"
	ch "gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/utils/container-helper"
	kh "gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/utils/kubernetes-helper"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"

	log "github.com/sirupsen/logrus"
)

var cu = ch.NewContainerUtil()
var ku = kh.NewKubernetesUtil()

type FileConsumer struct {
	dataChan chan constant.Data
	quitChan chan struct{}
	file     string
	cache    *cache.Cache
	k8sCache *cache.Cache
	cu       ch.ContainerUtil
	ku       kh.KubernetesUtil
	kubeStop chan struct{}
}

func (cc *FileConsumer) Init(dataChan chan constant.Data) error {
	cc.dataChan = dataChan
	cc.quitChan = make(chan struct{}, 1)
	cc.file = "/data/syscall.json"
	cc.cache = cache.New(10*time.Second, 5*time.Minute)
	cc.k8sCache = cache.New(cache.NoExpiration, 5*time.Minute)
	cc.cu = ch.NewContainerUtil()
	cc.ku = kh.NewKubernetesUtil()

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

type FileEntry struct {
	EventInfo constant.EventInfoT    `json:"EventInfo"`
	ExtraInfo map[string]interface{} `json:"ExtraInfo"`
}

func (cc *FileConsumer) processSyscall(event *constant.TotalData, f *os.File) error {
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
	if !(s == "socket" || s == "open" || s == "openat" || s == "execve" || s == "dup2" || s == "chroot") {
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
	if info.PodName == "" {
		log.Debugf("Host process: %d", pid)
		return fmt.Errorf("Host process: %d", pid)
	}
	out := map[string]interface{}{}
	v := reflect.ValueOf(*info)
	typeOfS := v.Type()
	for i := 0; i < v.NumField(); i++ {
		out[typeOfS.Field(i).Name] = v.Field(i).Interface()
	}
	for key, element := range ExtraInfo {
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
		if ExtraInfo["socket__family"].(uint64) == 2 {
			if ExtraInfo["socket__protocol"].(uint64) != 132 {
				return nil
			}
		}
		// Other socket detections are to be sent for alerting
	} else if info.Syscall == "dup2" {
		_, found := cc.cache.Get(info.ContainerID + " " + strconv.Itoa(pid) + " " + strconv.FormatUint(ExtraInfo["dup2__oldfd"].(uint64), 10))
		if found {
			log.Info("Reverse shell attempt with socket/dup2 detected")
			out["reverse_shell_socket_dup2"] = "true"
		} else {
			// If there is no match with a socket fd in the same pod, we don't want to track this dup2 syscall
			return nil
		}
	} else if info.Syscall == "chroot" {
		if info.PodName != "" {
			x, found := cc.k8sCache.Get(info.ContainerID)
			kubeInfo := x.(*kh.KubeSelectedInfo)
			if found {
				for _, hostVolumeMountPath := range kubeInfo.HostVolumeMountPaths {
					if strings.Contains(hostVolumeMountPath, out["chroot__filename"].(string)) {
						log.Info("Container escape with chroot detected")
						out["chroot_container_escape"] = "true"
						break
					}
				}
			}
		}
	}
	log.Info(out)
	jsonStr, _ := json.Marshal(out)
	if _, err := f.WriteString(string(jsonStr) + "\n"); err != nil {
		log.Error("Error writing json to file", err)
		return err
	}
	log.Info("Successfully saved to file")
	return nil
}

func (cc *FileConsumer) Consume(_ *utils.NsMap) {
	f, err := os.OpenFile(cc.file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	for data := range cc.dataChan {
		switch event := data.(type) {
		case *constant.TotalData:
			go func(event *constant.TotalData) {
				defer func() {
					if r := recover(); r != nil {
						logging.GetLogger().Error().Msgf("error : %v. stack: %s", r, debug.Stack())
					}
				}()

				err := cc.processSyscall(event, f)
				if err != nil {
					time.AfterFunc(10*time.Second, func() { cc.processSyscall(event, f) })
				}
			}(event)
		default:
			log.Warn("SeccompConsumer data type should be one of listed type.")
		}
	}
	cc.kubeStop <- struct{}{}
	cc.quitChan <- struct{}{}
}

func (cc *FileConsumer) Stop() {
	<-cc.quitChan
}

func NewFileConsumer() *FileConsumer {
	return &FileConsumer{}
}
