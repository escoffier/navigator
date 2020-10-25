package consumer

import (
	"C"
	"reflect"
	"strings"
	"unsafe"

	"gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/utils"

	log "github.com/sirupsen/logrus"
	"gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/constant"
)
import (
	"fmt"
)

type JsonConsumer struct {
	dataChan chan constant.Data
	quitChan chan struct{}
}

func (cc *JsonConsumer) Init(dataChan chan constant.Data) error {
	cc.dataChan = dataChan
	cc.quitChan = make(chan struct{}, 1)
	return nil
}

type Logentry struct {
	EventInfo constant.EventInfoT
	ExtraInfo map[string]interface{}
}

func (cc *JsonConsumer) Consume(_ *utils.NsMap) {
	for data := range cc.dataChan {
		switch event := data.(type) {
		case *constant.TotalData:
			ExtraInfo := make(map[string]interface{})
			if event.IsSyscall {
				syscall := C.GoString((*C.char)(unsafe.Pointer(&event.EventInfo.EventName)))
				if syscall == "exit" {
					continue
				} // Bytedid generates EXIT, yet EXIT is not specified
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
			jsondata := Logentry{event.EventInfo, ExtraInfo}
			fmt.Println(jsondata)
		default:
			log.Warn("JsonConsumer data type should be one of listed type.")
		}
	}
	cc.quitChan <- struct{}{}
}

func (cc *JsonConsumer) Stop() {
	<-cc.quitChan
}

func NewJsonConsumer() *JsonConsumer {
	return &JsonConsumer{}
}
