package consumer

import (
	"C"
	"encoding/json"
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

var cu = ch.NewContainerUtil()
var ku = kh.NewKubernetesUtil()

type FileConsumer struct {
	dataChan chan constant.Data
	quitChan chan struct{}
	file     string
	cache    *cache.Cache
}

func (cc *FileConsumer) Init(dataChan chan constant.Data) error {
	cc.dataChan = dataChan
	cc.quitChan = make(chan struct{}, 1)
	cc.file = "/data/syscall.json"
	cc.cache = cache.New(10*time.Second, 10*time.Second)
	return nil
}

type FileEntry struct {
	EventInfo constant.EventInfoT    `json:"EventInfo"`
	ExtraInfo map[string]interface{} `json:"ExtraInfo"`
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
			ExtraInfo := make(map[string]interface{})
			if event.IsSyscall {
				syscall := C.GoString((*C.char)(unsafe.Pointer(&event.EventInfo.EventName)))
				if syscall == "exit" {
					continue
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
			pid := int(event.EventInfo.Pid)
			ptid := int(event.EventInfo.Ptgid)
			containerPID, err := cu.GetContainerPid(pid)
			if err != nil {
				log.Error("Problem getting container ID", err)
				continue
			}
			if containerPID == 1 {
				log.Infof("Checking if parent %d of %d still has docker context\n", pid, ptid)
				containerPID, err = cu.GetContainerPid(ptid)
				if err != nil {
					log.Error("Problem getting container ID", err)
					continue
				}
			}
			if containerPID == 1 {
				log.Infof("Host process: %d", pid)
				continue
			}
			if pid > 0 {
				info, err := ku.LookupPod(containerPID, pid, ExtraInfo["syscall"].(string))
				if err != nil {
					log.Error("Problem getting pod ID", err)
				} else {
					if info.DockerPID <= 0 {
						info, err = ku.LookupPod(containerPID, ptid, ExtraInfo["syscall"].(string))
						if err != nil {
							log.Error("Problem getting pod ID", err)
							continue
						}
					}
					if info.DockerPID <= 0 {
						log.Infof("Host process: %d", pid)
						continue
					} else {
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
									continue
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
								continue
							}
						}
						log.Info(out)
						jsonStr, _ := json.Marshal(out)
						if _, err := f.WriteString(string(jsonStr) + "\n"); err != nil {
							log.Error("Error writing json to file", err)
							continue
						}
						log.Info("Successfully saved to file")
					}
				}
			}
		default:
			log.Warn("FileConsumer data type should be one of listed type.")
		}
	}
	cc.quitChan <- struct{}{}
}

func (cc *FileConsumer) Stop() {
	<-cc.quitChan
}

func NewFileConsumer() *FileConsumer {
	return &FileConsumer{}
}
