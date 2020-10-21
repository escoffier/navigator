package consumer

import (
	"C"
	"fmt"
	"reflect"
	"strings"
	"syscall"
	"unsafe"

	"gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/utils"

	"gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/constant"
	log "github.com/sirupsen/logrus"
)

type PrintConsumer struct {
	dataChan chan constant.Data
	// It should be buffered channel with size 1
	quitChan chan struct{}
}

func (cc *PrintConsumer) Init(dataChan chan constant.Data) error {
	cc.dataChan = dataChan
	cc.quitChan = make(chan struct{}, 1)
	return nil
}

func PrintTargetField(totalStruct *constant.TotalData, syscall string, args []string) {
	v := reflect.ValueOf(*totalStruct)
	c := 0
	for _, arg := range args {
		argField := syscall + arg
		if f := v.FieldByName(argField); f.IsValid() {
			fmt.Printf("%s:%v ", argField, f)
			c++
		}
	}
	fmt.Printf("Return code: %d", totalStruct.EventInfo.Ret)
	if c != len(args) {
		log.Warnf("%d arguments accepted but %d fields printed.", len(args), c)
	}
}

func c2go(cstr string, public bool) string {
	cstr = strings.ToLower(cstr)
	result := ""
	capitalFlag := public
	for _, i := range cstr {
		if strings.Contains("abcdefghijklmnopqrstuvwxyz0123456789", string(i)) {
			if capitalFlag {
				result += strings.ToUpper(string(i))
				capitalFlag = false
			} else {
				result += string(i)
			}
		} else {
			capitalFlag = true
		}
	}
	return result
}

func ParseProtocol(proto uint32) string {
	var protoString strings.Builder
	protoFamily := (proto >> 16) & 0xff
	socketType := proto & 0xff
	// socketProtocol := proto & 0xff00
	if socketType == syscall.SOCK_STREAM {
		protoString.WriteString("TCP")
	} else if socketType == syscall.SOCK_DGRAM {
		protoString.WriteString("UDP")
	} else if socketType == syscall.SOCK_RAW {
		protoString.WriteString("RAW")
	}

	if protoFamily == syscall.AF_INET {
		protoString.WriteString("V4")
	} else if protoFamily == syscall.AF_INET6 {
		protoString.WriteString("V6")
	}

	return protoString.String()
}

func PrintEventInfo(event *constant.TotalData) {
	syscall := C.GoString((*C.char)(unsafe.Pointer(&event.EventInfo.EventName)))
	fmt.Printf("%d [%s] Process=%s(Pid:%d Tid:%d PTid:%d PPid:%d Gid:%d Uid:%d Egid:%d, Euid:%d NSid:%d FdType: %v, FdInodes: %v FdSports: %v, FdDports: %v, FdSaddr: [%s, %s, %s, %s, %s], FdDaddr: [%s, %s, %s, %s, %s], Input Major: %d, Minor: %d)] ", event.EventInfo.Ts,
		strings.ToUpper(syscall),
		C.GoString((*C.char)(unsafe.Pointer(&event.EventInfo.ProcName))),
		event.EventInfo.Pid,
		event.EventInfo.Tid,
		event.EventInfo.Ptid,
		event.EventInfo.Ptgid,
		event.EventInfo.Gid,
		event.EventInfo.Uid,
		event.EventInfo.Egid,
		event.EventInfo.Euid,
		event.EventInfo.Nsid,
		event.EventInfo.FileType,
		event.EventInfo.Inodes,
		event.EventInfo.Sports,
		event.EventInfo.Dports,
		utils.InttoIP4(int64(event.EventInfo.Saddrs[0])),
		utils.InttoIP4(int64(event.EventInfo.Saddrs[1])),
		utils.InttoIP4(int64(event.EventInfo.Saddrs[2])),
		utils.InttoIP4(int64(event.EventInfo.Saddrs[3])),
		utils.InttoIP4(int64(event.EventInfo.Saddrs[4])),
		utils.InttoIP4(int64(event.EventInfo.Daddrs[0])),
		utils.InttoIP4(int64(event.EventInfo.Daddrs[1])),
		utils.InttoIP4(int64(event.EventInfo.Daddrs[2])),
		utils.InttoIP4(int64(event.EventInfo.Daddrs[3])),
		utils.InttoIP4(int64(event.EventInfo.Daddrs[4])),
		event.EventInfo.Major,
		event.EventInfo.Minor,
	)
}

func (cc *PrintConsumer) Consume(_ *utils.NsMap) {
	for data := range cc.dataChan {
		switch event := data.(type) {
		case *constant.TotalData:
			// Container
			//nsMap.Lock.RLock()
			//container := nsMap.Data[event.EventInfo.Nsid]
			//nsMap.Lock.RUnlock()
			//if container.Id != "" {
			//	fmt.Printf("Container:%s(%s) ", container.Name, container.Id[:8])
			//}

			// TTY
			//tty, err := utils.GetTtyByPid(event.EventInfo.Pid)
			//if err == nil {
			//	fmt.Printf("TTY:%s ", tty)
			//}

			// Real execute path
			//exePath, err := utils.GetExeByPid(event.EventInfo.Pid)
			//if err == nil {
			//	fmt.Printf("ExePath:%s ", exePath)
			//}

			if event.IsSyscall {
				// Basic information
				PrintEventInfo(event)
				// Syscall fields
				syscall := C.GoString((*C.char)(unsafe.Pointer(&event.EventInfo.EventName)))
				fieldsTypes := utils.GetFieldsAbbr(&syscall)
				var args []string
				for v, _ := range fieldsTypes {
					args = append(args, c2go(v, true))
				}
				PrintTargetField(event, c2go(syscall, true), args)
				fmt.Println()
			} else {
				// Basic information
				fmt.Printf("%d [Proto%s] Process=%s(Pid:%d Tid:%d PTid:%d PPid:%d Gid:%d Uid:%d Egid:%d Euid:%d NSid:%d)] ", event.EventInfo.Ts,
					ParseProtocol(event.EventInfo.Protos[3]),
					C.GoString((*C.char)(unsafe.Pointer(&event.EventInfo.ProcName))),
					event.EventInfo.Pid,
					event.EventInfo.Tid,
					event.EventInfo.Ptid,
					event.EventInfo.Ptgid,
					event.EventInfo.Gid,
					event.EventInfo.Uid,
					event.EventInfo.Egid,
					event.EventInfo.Euid,
					event.EventInfo.Nsid)

				// Socket in
				sip := utils.InttoIP4(int64(event.EventInfo.Saddrs[3]))
				dip := utils.InttoIP4(int64(event.EventInfo.Daddrs[3]))
				fmt.Printf("Act:%s Ret:%d NetNS:%d sIP:%s dIP:%s sPort:%d dPort:%d ",
					C.GoString((*C.char)(unsafe.Pointer(&event.EventInfo.EventName))), event.EventInfo.Ret,
					event.EventInfo.Netns, sip, dip, event.EventInfo.Sports[3], event.EventInfo.Dports[3])

				fmt.Println()

			}
		default:
			log.Warn("PrintConumser data type should be one of listed type.")
		}
	}
	cc.quitChan <- struct{}{}
}

func (cc *PrintConsumer) Stop() {
	<-cc.quitChan
}

func NewPrintConsumer() *PrintConsumer {
	return &PrintConsumer{}
}
