package consumer

import (
	"C"
	"container/heap"
	"fmt"
	"unsafe"

	"gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/constant"
	"gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/utils"
	log "github.com/sirupsen/logrus"
)

type Item struct {
	data  constant.Data
	index int
}

type priorityQueue []*Item

func (pq priorityQueue) Len() int { return len(pq) }

func (pq priorityQueue) Less(i, j int) bool {
	var ts_i, ts_j uint64
	event_i := pq[i].data
	event_j := pq[j].data
	switch event := event_i.(type) {
	case *constant.TotalData:
		ts_i = event.EventInfo.Ts
	default:
		log.Fatal("Impossible type")
	}

	switch event := event_j.(type) {
	case *constant.TotalData:
		ts_j = event.EventInfo.Ts
	default:
		log.Fatal("Impossible type")
	}
	return ts_i < ts_j
}

func (pq priorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].index = i
	pq[j].index = j
}

func (pq *priorityQueue) Push(x interface{}) {
	n := len(*pq)
	item := x.(*Item)
	item.index = n
	*pq = append(*pq, item)
}

func (pq *priorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil  // avoid memory leak
	item.index = -1 // for safety
	*pq = old[0 : n-1]
	return item
}

type CollectConsumer struct {
	dataChan chan constant.Data
	quitChan chan struct{}
	pidMap   map[uint32]priorityQueue
	tidMap   map[uint32][]uint64
}

func (cc *CollectConsumer) Init(dataChan chan constant.Data) error {
	cc.dataChan = dataChan
	cc.quitChan = make(chan struct{}, 1)
	cc.pidMap = make(map[uint32]priorityQueue, 4)
	cc.tidMap = make(map[uint32][]uint64, 100)
	return nil
}

func (cc *CollectConsumer) Consume(*utils.NsMap) {
	for data := range cc.dataChan {
		switch event := data.(type) {
		case *constant.TotalData:
			if arr, ok := cc.tidMap[event.EventInfo.Tid]; !ok {
				arr = make([]uint64, 0, 100)
				arr = append(arr, event.EventInfo.Ts)
				cc.tidMap[event.EventInfo.Tid] = arr
			} else {
				if event.EventInfo.Ts < arr[len(arr)-1] {
					log.Errorf("Last time: %d, current time: %d, Not ordered in thread %d, Process: %d. procName: %s.",
						arr[len(arr)-1], event.EventInfo.Ts, event.EventInfo.Tid, event.EventInfo.Pid, utils.CBytesToGoString(event.EventInfo.ProcName[:]))
				}
				arr = append(arr, event.EventInfo.Ts)
				cc.tidMap[event.EventInfo.Tid] = arr
			}
			// if pq, ok := cc.pidMap[event.EventInfo.Pid]; !ok {
			// 	pq = make(priorityQueue, 0, 100)
			// 	heap.Init(&pq)
			// 	heap.Push(&pq, &Item{data: event})
			// 	cc.pidMap[event.EventInfo.Pid] = pq
			// } else {
			// 	heap.Push(&pq, &Item{data: event})
			// 	cc.pidMap[event.EventInfo.Pid] = pq
			// }
		default:
			log.Fatal("Program should never run here.")
		}
	}
	for pid, pq := range cc.pidMap {
		fmt.Printf("Pid: %d system calls: ****************************************************\n", pid)
		for pq.Len() > 0 {
			item := heap.Pop(&pq).(*Item)
			data := item.data
			// Syscall fields
			switch event := data.(type) {
			case *constant.TotalData:
				if event.IsSyscall {
					PrintEventInfo(event)
					syscall := C.GoString((*C.char)(unsafe.Pointer(&event.EventInfo.EventName)))
					fieldsTypes := utils.GetFieldsAbbr(&syscall)
					var args []string
					for v, _ := range fieldsTypes {
						args = append(args, c2go(v, true))
					}
					PrintTargetField(event, c2go(syscall, true), args)
					fmt.Println()

				} else {
					sip := utils.InttoIP4(int64(event.EventInfo.Saddrs[3]))
					dip := utils.InttoIP4(int64(event.EventInfo.Daddrs[3]))
					fmt.Printf("[Proto %s] Act:%s Ret:%d NetNS:%d sIP:%s dIP:%s sPort:%d dPort:%d ",
						ParseProtocol(event.EventInfo.Protos[3]), C.GoString((*C.char)(unsafe.Pointer(&event.EventInfo.EventName))),
						event.EventInfo.Ret,
						event.EventInfo.Netns, sip, dip, event.EventInfo.Sports[3], event.EventInfo.Dports[3])
					fmt.Println()
				}
			default:
				log.Fatalf("Impossbile data")
			}
		}
	}

	cc.quitChan <- struct{}{}
}

func (cc *CollectConsumer) Stop() {
	<-cc.quitChan
}

func NewCollectConsumer() *CollectConsumer {
	return &CollectConsumer{}
}
