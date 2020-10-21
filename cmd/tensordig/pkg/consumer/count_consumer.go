package consumer

import (
	"C"

	"fmt"
	"reflect"
	"time"
	"unsafe"

	"gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/producer"
	"gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/utils"
	log "github.com/sirupsen/logrus"

	"gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/constant"
)

type CountConsumer struct {
	dataChan        chan constant.Data
	syscallCountMap map[string]int
	// It should be buffered channel with size 1
	quitChan chan struct{}
	PidCount map[uint32]bool
	Exit map[uint32]bool
}

func (cc *CountConsumer) Init(dataChan chan constant.Data) error {
	cc.dataChan = dataChan
	cc.syscallCountMap = make(map[string]int)
	cc.quitChan = make(chan struct{}, 1)
	cc.PidCount = make(map[uint32]bool, 10000)
	cc.Exit = make(map[uint32]bool, 10000)
	return nil
}

func (cc *CountConsumer) Consume(_ *utils.NsMap) {
	timeChan := make(chan struct{}, 1)
	go func() {
		for {
			time.Sleep(30 * time.Second)
			timeChan <- struct{}{}
		}
	}()
	for data := range cc.dataChan {
		switch d := data.(type) {
		case *constant.TotalData:
			syscall := C.GoString((*C.char)(unsafe.Pointer(&d.EventInfo.EventName)))
			if "exit" == syscall {
				cc.Exit[d.EventInfo.Pid] = true
			}else{
				cc.PidCount[d.EventInfo.Pid] = true
			}
			cc.syscallCountMap[syscall]++
		case *producer.SocketData:
			cc.syscallCountMap[C.GoString((*C.char)(unsafe.Pointer(&d.EventInfo.EventName)))]++
		default:
			log.Warn(reflect.TypeOf(d))
			log.Warn("CountConumser data type should be one of listed type.")
		}
		select {
		case <-timeChan:
			num := 0
			for pid := range cc.PidCount {
				if !cc.Exit[pid] {
					num++
				}
			}
			
			log.Errorf("#Pids in kernel: %d", num)
		default:
		}
	}
	fmt.Println("========COUNT========")
	for k, v := range cc.syscallCountMap {
		fmt.Printf("%10s:%d\n", k, v)
	}
	cc.quitChan <- struct{}{}
}

func (cc *CountConsumer) Stop() {
	<-cc.quitChan
}

func NewCountConsumer() *CountConsumer {
	return &CountConsumer{}
}
