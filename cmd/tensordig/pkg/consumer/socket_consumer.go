package consumer

import (
	"C"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"reflect"
	"strings"
	"unsafe"

	"gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/constant"
	"gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/utils"

	log "github.com/sirupsen/logrus"
)

type SocketConsumer struct {
	dataChan chan constant.Data
	quitChan chan struct{}
	socket   string
}

func (cc *SocketConsumer) Init(dataChan chan constant.Data) error {
	cc.dataChan = dataChan
	cc.quitChan = make(chan struct{}, 1)
	cc.socket = "/data/syscall.sock"
	return nil
}

type SocketEntry struct {
	EventInfo constant.EventInfoT    `json:"EventInfo"`
	ExtraInfo map[string]interface{} `json:"ExtraInfo"`
}

func checkFile(filename string) error {
	_, err := os.Stat(filename)
	if os.IsNotExist(err) {
		_, err := os.Create(filename)
		if err != nil {
			return err
		}
	}
	return nil
}

func (cc *SocketConsumer) Consume(_ *utils.NsMap) {
	c, err := net.Dial("unix", cc.socket)
	if err != nil {
		log.Println(err)
	}
	encode := json.NewEncoder(c)
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
			jsondata := SocketEntry{event.EventInfo, ExtraInfo}
			err = encode.Encode(jsondata)
			if err != nil {
				fmt.Printf("ERROR: %+v\n", jsondata)
			} else {
				fmt.Println(jsondata)
			}
		default:
			log.Warn("SocketConsumer data type should be one of listed type.")
		}
	}
	cc.quitChan <- struct{}{}
}

func (cc *SocketConsumer) Stop() {
	<-cc.quitChan
}

func NewSocketConsumer() *SocketConsumer {
	return &SocketConsumer{}
}
