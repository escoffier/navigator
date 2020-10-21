package producer

import (
	"C"
	"bytes"
	"encoding/binary"
	"unsafe"

	"gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/constant"
	"gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/utils"
)
import "fmt"

func (m *Manager) Deserialize(byteData []byte) (*constant.TotalData, error) {
	var data constant.TotalData
	event_name := utils.CBytesToGoString(byteData[:16])
	switch event_name {
	case "time":
		var event constant.TimeData
		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.TimeTloc = event.Tloc
		 
	case "migrate_pages":
		var event constant.MigratePagesData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.MigratePagesPid = event.Pid
		data.MigratePagesMaxnode = event.Maxnode
		data.MigratePagesOldNodes = event.OldNodes
		data.MigratePagesNewNodes = event.NewNodes
		 
	case "lsetxattr":
		var event constant.LsetxattrData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.LsetxattrPathname = C.GoString((*C.char)(unsafe.Pointer(&event.Pathname)))
		data.LsetxattrName = C.GoString((*C.char)(unsafe.Pointer(&event.Name)))
		data.LsetxattrValue = event.Value
		data.LsetxattrSize = event.Size
		data.LsetxattrFlags = event.Flags
		 
	case "clock_getres":
		var event constant.ClockGetresData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.ClockGetresWhichClock = event.WhichClock
		data.ClockGetresTp = event.Tp
		 
	case "set_tid_address":
		var event constant.SetTidAddressData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SetTidAddressTidptr = event.Tidptr
		 
	case "pipe2":
		var event constant.Pipe2Data

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.Pipe2Fildes = event.Fildes
		data.Pipe2Flags = event.Flags
		data.Pipe2Readfd = event.ReadFd
		data.Pipe2Writefd = event.WriteFd
		 
	case "sethostname":
		var event constant.SethostnameData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SethostnameName = C.GoString((*C.char)(unsafe.Pointer(&event.Name)))
		data.SethostnameLen = event.Len
		 
	case "dup3":
		var event constant.Dup3Data

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.Dup3Oldfd = event.Oldfd
		data.Dup3Newfd = event.Newfd
		data.Dup3Flags = event.Flags
		 
	case "umask":
		var event constant.UmaskData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.UmaskMask = event.Mask
		 
	case "exit_group":
		var event constant.ExitGroupData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.ExitGroupErrorCode = event.ErrorCode
		 
	case "set_robust_list":
		var event constant.SetRobustListData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SetRobustListHead = event.Head
		data.SetRobustListLen = event.Len
		 
	case "iopl":
		var event constant.IoplData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.IoplLevel = event.Level
		 
	case "lgetxattr":
		var event constant.LgetxattrData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.LgetxattrPathname = C.GoString((*C.char)(unsafe.Pointer(&event.Pathname)))
		data.LgetxattrName = C.GoString((*C.char)(unsafe.Pointer(&event.Name)))
		data.LgetxattrValue = event.Value
		data.LgetxattrSize = event.Size
		 
	case "kill":
		var event constant.KillData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.KillPid = event.Pid
		data.KillSig = event.Sig
		 
	case "pread64":
		var event constant.Pread64Data

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.Pread64Fd = event.Fd
		data.Pread64Buf = C.GoString((*C.char)(unsafe.Pointer(&event.Buf)))
		data.Pread64Count = event.Count
		data.Pread64Pos = event.Pos
		 
	case "newfstatat":
		var event constant.NewfstatatData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.NewfstatatDfd = event.Dfd
		data.NewfstatatFilename = C.GoString((*C.char)(unsafe.Pointer(&event.Filename)))
		data.NewfstatatStatbuf = event.Statbuf
		data.NewfstatatFlag = event.Flag
		 
	case "newlstat":
		var event constant.NewlstatData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.NewlstatFilename = C.GoString((*C.char)(unsafe.Pointer(&event.Filename)))
		data.NewlstatStatbuf = event.Statbuf
		 
	case "write":
		var event constant.WriteData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.WriteFd = event.Fd
		data.WriteBuf = C.GoString((*C.char)(unsafe.Pointer(&event.Buf)))
		data.WriteCount = event.Count
		 
	case "setregid":
		var event constant.SetregidData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SetregidRgid = event.Rgid
		data.SetregidEgid = event.Egid
		 
	case "ustat":
		var event constant.UstatData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.UstatDev = event.Dev
		data.UstatUbuf = event.Ubuf
		 
	case "pause":
		var event constant.PauseData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		 
	case "getrlimit":
		var event constant.GetrlimitData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.GetrlimitResource = event.Resource
		data.GetrlimitRlim = event.Rlim
		 
	case "tkill":
		var event constant.TkillData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.TkillPid = event.Pid
		data.TkillSig = event.Sig
		 
	case "dup2":
		var event constant.Dup2Data

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.Dup2Oldfd = event.Oldfd
		data.Dup2Newfd = event.Newfd
		 
	case "clock_adjtime":
		var event constant.ClockAdjtimeData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.ClockAdjtimeWhichClock = event.WhichClock
		data.ClockAdjtimeUtx = event.Utx
		 
	case "rt_sigqueueinfo":
		var event constant.RtSigqueueinfoData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.RtSigqueueinfoPid = event.Pid
		data.RtSigqueueinfoSig = event.Sig
		data.RtSigqueueinfoUinfo = event.Uinfo
		 
	case "utime":
		var event constant.UtimeData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.UtimeFilename = C.GoString((*C.char)(unsafe.Pointer(&event.Filename)))
		data.UtimeTimes = event.Times
		 
	case "setxattr":
		var event constant.SetxattrData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SetxattrPathname = C.GoString((*C.char)(unsafe.Pointer(&event.Pathname)))
		data.SetxattrName = C.GoString((*C.char)(unsafe.Pointer(&event.Name)))
		data.SetxattrValue = event.Value
		data.SetxattrSize = event.Size
		data.SetxattrFlags = event.Flags
		 
	case "membarrier":
		var event constant.MembarrierData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.MembarrierCmd = event.Cmd
		data.MembarrierFlags = event.Flags
		 
	case "getegid":
		var event constant.GetegidData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		 
	case "mlock":
		var event constant.MlockData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.MlockStart = event.Start
		data.MlockLen = event.Len
		 
	case "tee":
		var event constant.TeeData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.TeeFdin = event.Fdin
		data.TeeFdout = event.Fdout
		data.TeeLen = event.Len
		data.TeeFlags = event.Flags
		 
	case "setpgid":
		var event constant.SetpgidData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SetpgidPid = event.Pid
		data.SetpgidPgid = event.Pgid
		 
	case "utimes":
		var event constant.UtimesData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.UtimesFilename = C.GoString((*C.char)(unsafe.Pointer(&event.Filename)))
		data.UtimesUtimes = event.Utimes
		 
	case "lremovexattr":
		var event constant.LremovexattrData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.LremovexattrPathname = C.GoString((*C.char)(unsafe.Pointer(&event.Pathname)))
		data.LremovexattrName = C.GoString((*C.char)(unsafe.Pointer(&event.Name)))
		 
	case "link":
		var event constant.LinkData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.LinkOldname = C.GoString((*C.char)(unsafe.Pointer(&event.Oldname)))
		data.LinkNewname = C.GoString((*C.char)(unsafe.Pointer(&event.Newname)))
		 
	case "readv":
		var event constant.ReadvData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.ReadvFd = event.Fd
		data.ReadvVec = event.Vec
		data.ReadvVlen = event.Vlen
		 
	case "futex":
		var event constant.FutexData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.FutexUaddr = event.Uaddr
		data.FutexOp = event.Op
		data.FutexVal = event.Val
		data.FutexUtime = event.Utime
		data.FutexUaddr2 = event.Uaddr2
		data.FutexVal3 = event.Val3
		 
	case "getxattr":
		var event constant.GetxattrData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.GetxattrPathname = C.GoString((*C.char)(unsafe.Pointer(&event.Pathname)))
		data.GetxattrName = C.GoString((*C.char)(unsafe.Pointer(&event.Name)))
		data.GetxattrValue = event.Value
		data.GetxattrSize = event.Size
		 
	case "sched_get_priority_max":
		var event constant.SchedGetPriorityMaxData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SchedGetPriorityMaxPolicy = event.Policy
		 
	case "preadv2":
		var event constant.Preadv2Data

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.Preadv2Fd = event.Fd
		data.Preadv2Vec = event.Vec
		data.Preadv2Vlen = event.Vlen
		data.Preadv2PosL = event.PosL
		data.Preadv2PosH = event.PosH
		data.Preadv2Flags = event.Flags
		 
	case "readlinkat":
		var event constant.ReadlinkatData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.ReadlinkatDfd = event.Dfd
		data.ReadlinkatPathname = C.GoString((*C.char)(unsafe.Pointer(&event.Pathname)))
		data.ReadlinkatBuf = C.GoString((*C.char)(unsafe.Pointer(&event.Buf)))
		data.ReadlinkatBufsiz = event.Bufsiz
		 
	case "prctl":
		var event constant.PrctlData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.PrctlOption = event.Option
		data.PrctlArg2 = event.Arg2
		data.PrctlArg3 = event.Arg3
		data.PrctlArg4 = event.Arg4
		data.PrctlArg5 = event.Arg5
		 
	case "renameat":
		var event constant.RenameatData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.RenameatOlddfd = event.Olddfd
		data.RenameatOldname = C.GoString((*C.char)(unsafe.Pointer(&event.Oldname)))
		data.RenameatNewdfd = event.Newdfd
		data.RenameatNewname = C.GoString((*C.char)(unsafe.Pointer(&event.Newname)))
		 
	case "renameat2":
		var event constant.Renameat2Data

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.Renameat2Olddfd = event.Olddfd
		data.Renameat2Oldname = C.GoString((*C.char)(unsafe.Pointer(&event.Oldname)))
		data.Renameat2Newdfd = event.Newdfd
		data.Renameat2Newname = C.GoString((*C.char)(unsafe.Pointer(&event.Newname)))
		data.Renameat2Flags = event.Flags
		 
	case "sendmmsg":
		var event constant.SendmmsgData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SendmmsgFd = event.Fd
		data.SendmmsgMmsg = event.Mmsg
		data.SendmmsgVlen = event.Vlen
		data.SendmmsgFlags = event.Flags
		 
	case "modify_ldt":
		var event constant.ModifyLdtData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.ModifyLdtFunc = event.Func
		data.ModifyLdtPtr = event.Ptr
		data.ModifyLdtBytecount = event.Bytecount
		 
	case "close":
		var event constant.CloseData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.CloseFd = event.Fd
		 
	case "ioprio_get":
		var event constant.IoprioGetData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.IoprioGetWhich = event.Which
		data.IoprioGetWho = event.Who
		 
	case "setreuid":
		var event constant.SetreuidData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SetreuidRuid = event.Ruid
		data.SetreuidEuid = event.Euid
		 
	case "sendfile64":
		var event constant.Sendfile64Data

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.Sendfile64OutFd = event.OutFd
		data.Sendfile64InFd = event.InFd
		data.Sendfile64Offset = event.Offset
		data.Sendfile64Count = event.Count
		 
	case "statfs":
		var event constant.StatfsData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.StatfsPathname = C.GoString((*C.char)(unsafe.Pointer(&event.Pathname)))
		data.StatfsBuf = event.Buf
		 
	case "getpriority":
		var event constant.GetpriorityData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.GetpriorityWhich = event.Which
		data.GetpriorityWho = event.Who
		 
	case "truncate":
		var event constant.TruncateData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.TruncatePath = C.GoString((*C.char)(unsafe.Pointer(&event.Path)))
		data.TruncateLength = event.Length
		 
	case "getcpu":
		var event constant.GetcpuData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.GetcpuCpup = event.Cpup
		data.GetcpuNodep = event.Nodep
		data.GetcpuUnused = event.Unused
		 
	case "shmat":
		var event constant.ShmatData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.ShmatShmid = event.Shmid
		data.ShmatShmaddr = C.GoString((*C.char)(unsafe.Pointer(&event.Shmaddr)))
		data.ShmatShmflg = event.Shmflg
		 
	case "swapon":
		var event constant.SwaponData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SwaponSpecialfile = C.GoString((*C.char)(unsafe.Pointer(&event.Specialfile)))
		data.SwaponSwapFlags = event.SwapFlags
		 
	case "waitid":
		var event constant.WaitidData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.WaitidWhich = event.Which
		data.WaitidUpid = event.Upid
		data.WaitidInfop = event.Infop
		data.WaitidOptions = event.Options
		data.WaitidRu = event.Ru
		 
	case "sync_file_range":
		var event constant.SyncFileRangeData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SyncFileRangeFd = event.Fd
		data.SyncFileRangeOffset = event.Offset
		data.SyncFileRangeNbytes = event.Nbytes
		data.SyncFileRangeFlags = event.Flags
		 
	case "sched_rr_get_interval":
		var event constant.SchedRrGetIntervalData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SchedRrGetIntervalPid = event.Pid
		data.SchedRrGetIntervalInterval = event.Interval
		 
	case "sched_getscheduler":
		var event constant.SchedGetschedulerData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SchedGetschedulerPid = event.Pid
		 
	case "signalfd":
		var event constant.SignalfdData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SignalfdUfd = event.Ufd
		data.SignalfdUserMask = event.UserMask
		data.SignalfdSizemask = event.Sizemask
		 
	case "accept4":
		var event constant.Accept4Data

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.Accept4Fd = event.Fd
		data.Accept4UpeerSockaddr = event.UpeerSockaddr
		data.Accept4UpeerAddrlen = event.UpeerAddrlen
		data.Accept4Flags = event.Flags
		 
	case "io_destroy":
		var event constant.IoDestroyData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.IoDestroyCtx = event.Ctx
		 
	case "shutdown":
		var event constant.ShutdownData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.ShutdownFd = event.Fd
		data.ShutdownHow = event.How
		 
	case "execveat":
		var event constant.ExecveatData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.ExecveatFd = event.Fd
		data.ExecveatFilename = C.GoString((*C.char)(unsafe.Pointer(&event.Filename)))
		data.ExecveatArgv1 = C.GoString((*C.char)(unsafe.Pointer(&event.Argv1)))
		data.ExecveatArgv2 = C.GoString((*C.char)(unsafe.Pointer(&event.Argv2)))
		data.ExecveatArgv3 = C.GoString((*C.char)(unsafe.Pointer(&event.Argv3)))
		data.ExecveatEnvp = event.Envp
		data.ExecveatFlags = event.Flags
		 
	case "readahead":
		var event constant.ReadaheadData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.ReadaheadFd = event.Fd
		data.ReadaheadOffset = event.Offset
		data.ReadaheadCount = event.Count
		 
	case "msgrcv":
		var event constant.MsgrcvData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.MsgrcvMsqid = event.Msqid
		data.MsgrcvMsgp = event.Msgp
		data.MsgrcvMsgsz = event.Msgsz
		data.MsgrcvMsgtyp = event.Msgtyp
		data.MsgrcvMsgflg = event.Msgflg
		 
	case "removexattr":
		var event constant.RemovexattrData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.RemovexattrPathname = C.GoString((*C.char)(unsafe.Pointer(&event.Pathname)))
		data.RemovexattrName = C.GoString((*C.char)(unsafe.Pointer(&event.Name)))
		 
	case "shmctl":
		var event constant.ShmctlData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.ShmctlShmid = event.Shmid
		data.ShmctlCmd = event.Cmd
		data.ShmctlBuf = event.Buf
		 
	case "sendmsg":
		var event constant.SendmsgData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SendmsgFd = event.Fd
		data.SendmsgMsg = event.Msg
		data.SendmsgFlags = event.Flags
		 
	case "setrlimit":
		var event constant.SetrlimitData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SetrlimitResource = event.Resource
		data.SetrlimitRlim = event.Rlim
		 
	case "munmap":
		var event constant.MunmapData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.MunmapAddr = event.Addr
		data.MunmapLen = event.Len
		 
	case "exit":
		var event constant.ExitData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.ExitErrorCode = event.ErrorCode
		 
	case "io_getevents":
		var event constant.IoGeteventsData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.IoGeteventsCtxId = event.CtxId
		data.IoGeteventsMinNr = event.MinNr
		data.IoGeteventsNr = event.Nr
		data.IoGeteventsEvents = event.Events
		data.IoGeteventsTimeout = event.Timeout
		 
	case "symlink":
		var event constant.SymlinkData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SymlinkOldname = C.GoString((*C.char)(unsafe.Pointer(&event.Oldname)))
		data.SymlinkNewname = C.GoString((*C.char)(unsafe.Pointer(&event.Newname)))
		 
	case "rt_sigpending":
		var event constant.RtSigpendingData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.RtSigpendingUset = event.Uset
		data.RtSigpendingSigsetsize = event.Sigsetsize
		 
	case "fanotify_init":
		var event constant.FanotifyInitData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.FanotifyInitFlags = event.Flags
		data.FanotifyInitEventFFlags = event.EventFFlags
		 
	case "geteuid":
		var event constant.GeteuidData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		 
	case "getpeername":
		var event constant.GetpeernameData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.GetpeernameFd = event.Fd
		data.GetpeernameUsockaddr = event.Usockaddr
		data.GetpeernameUsockaddrLen = event.UsockaddrLen
		 
	case "fsetxattr":
		var event constant.FsetxattrData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.FsetxattrFd = event.Fd
		data.FsetxattrName = C.GoString((*C.char)(unsafe.Pointer(&event.Name)))
		data.FsetxattrValue = event.Value
		data.FsetxattrSize = event.Size
		data.FsetxattrFlags = event.Flags
		 
	case "acct":
		var event constant.AcctData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.AcctName = C.GoString((*C.char)(unsafe.Pointer(&event.Name)))
		 
	case "times":
		var event constant.TimesData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.TimesTbuf = event.Tbuf
		 
	case "msgget":
		var event constant.MsggetData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.MsggetKey = event.Key
		data.MsggetMsgflg = event.Msgflg
		 
	case "inotify_add_watch":
		var event constant.InotifyAddWatchData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.InotifyAddWatchFd = event.Fd
		data.InotifyAddWatchPathname = C.GoString((*C.char)(unsafe.Pointer(&event.Pathname)))
		data.InotifyAddWatchMask = event.Mask
		 
	case "timerfd_gettime":
		var event constant.TimerfdGettimeData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.TimerfdGettimeUfd = event.Ufd
		data.TimerfdGettimeOtmr = event.Otmr
		 
	case "rt_tgsigqueueinfo":
		var event constant.RtTgsigqueueinfoData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.RtTgsigqueueinfoTgid = event.Tgid
		data.RtTgsigqueueinfoPid = event.Pid
		data.RtTgsigqueueinfoSig = event.Sig
		data.RtTgsigqueueinfoUinfo = event.Uinfo
		 
	case "timer_delete":
		var event constant.TimerDeleteData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.TimerDeleteTimerId = event.TimerId
		 
	case "pkey_alloc":
		var event constant.PkeyAllocData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.PkeyAllocFlags = event.Flags
		data.PkeyAllocInitVal = event.InitVal
		 
	case "setfsgid":
		var event constant.SetfsgidData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SetfsgidGid = event.Gid
		 
	case "tgkill":
		var event constant.TgkillData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.TgkillTgid = event.Tgid
		data.TgkillPid = event.Pid
		data.TgkillSig = event.Sig
		 
	case "setgid":
		var event constant.SetgidData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SetgidGid = event.Gid
		 
	case "adjtimex":
		var event constant.AdjtimexData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.AdjtimexTxcP = event.TxcP
		 
	case "fgetxattr":
		var event constant.FgetxattrData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.FgetxattrFd = event.Fd
		data.FgetxattrName = C.GoString((*C.char)(unsafe.Pointer(&event.Name)))
		data.FgetxattrValue = event.Value
		data.FgetxattrSize = event.Size
		 
	case "pkey_mprotect":
		var event constant.PkeyMprotectData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.PkeyMprotectStart = event.Start
		data.PkeyMprotectLen = event.Len
		data.PkeyMprotectProt = event.Prot
		data.PkeyMprotectPkey = event.Pkey
		 
	case "sched_setscheduler":
		var event constant.SchedSetschedulerData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SchedSetschedulerPid = event.Pid
		data.SchedSetschedulerPolicy = event.Policy
		data.SchedSetschedulerParam = event.Param
		 
	case "mq_notify":
		var event constant.MqNotifyData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.MqNotifyMqdes = event.Mqdes
		data.MqNotifyUNotification = event.UNotification
		 
	case "epoll_pwait":
		var event constant.EpollPwaitData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.EpollPwaitEpfd = event.Epfd
		data.EpollPwaitEvents = event.Events
		data.EpollPwaitMaxevents = event.Maxevents
		data.EpollPwaitTimeout = event.Timeout
		data.EpollPwaitSigmask = event.Sigmask
		data.EpollPwaitSigsetsize = event.Sigsetsize
		 
	case "syncfs":
		var event constant.SyncfsData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SyncfsFd = event.Fd
		 
	case "getrandom":
		var event constant.GetrandomData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.GetrandomBuf = C.GoString((*C.char)(unsafe.Pointer(&event.Buf)))
		data.GetrandomCount = event.Count
		data.GetrandomFlags = event.Flags
		 
	case "creat":
		var event constant.CreatData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.CreatPathname = C.GoString((*C.char)(unsafe.Pointer(&event.Pathname)))
		data.CreatMode = event.Mode
		 
	case "ppoll":
		var event constant.PpollData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.PpollUfds = event.Ufds
		data.PpollNfds = event.Nfds
		data.PpollTsp = event.Tsp
		data.PpollSigmask = event.Sigmask
		data.PpollSigsetsize = event.Sigsetsize
		 
	case "sync":
		var event constant.SyncData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		 
	case "futimesat":
		var event constant.FutimesatData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.FutimesatDfd = event.Dfd
		data.FutimesatFilename = C.GoString((*C.char)(unsafe.Pointer(&event.Filename)))
		data.FutimesatUtimes = event.Utimes
		 
	case "getuid":
		var event constant.GetuidData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		 
	case "kexec_load":
		var event constant.KexecLoadData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.KexecLoadEntry = event.Entry
		data.KexecLoadNrSegments = event.NrSegments
		data.KexecLoadSegments = event.Segments
		data.KexecLoadFlags = event.Flags
		 
	case "fanotify_mark":
		var event constant.FanotifyMarkData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.FanotifyMarkFanotifyFd = event.FanotifyFd
		data.FanotifyMarkFlags = event.Flags
		data.FanotifyMarkMask = event.Mask
		data.FanotifyMarkDfd = event.Dfd
		data.FanotifyMarkPathname = C.GoString((*C.char)(unsafe.Pointer(&event.Pathname)))
		 
	case "chroot":
		var event constant.ChrootData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.ChrootFilename = C.GoString((*C.char)(unsafe.Pointer(&event.Filename)))
		 
	case "select":
		var event constant.SelectData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SelectN = event.N
		data.SelectInp = event.Inp
		data.SelectOutp = event.Outp
		data.SelectExp = event.Exp
		data.SelectTvp = event.Tvp
		 
	case "getrusage":
		var event constant.GetrusageData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.GetrusageWho = event.Who
		data.GetrusageRu = event.Ru
		 
	case "pwritev":
		var event constant.PwritevData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.PwritevFd = event.Fd
		data.PwritevVec = event.Vec
		data.PwritevVlen = event.Vlen
		data.PwritevPosL = event.PosL
		data.PwritevPosH = event.PosH
		 
	case "getsockopt":
		var event constant.GetsockoptData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.GetsockoptFd = event.Fd
		data.GetsockoptLevel = event.Level
		data.GetsockoptOptname = event.Optname
		data.GetsockoptOptval = C.GoString((*C.char)(unsafe.Pointer(&event.Optval)))
		data.GetsockoptOptlen = event.Optlen
		 
	case "rename":
		var event constant.RenameData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.RenameOldname = C.GoString((*C.char)(unsafe.Pointer(&event.Oldname)))
		data.RenameNewname = C.GoString((*C.char)(unsafe.Pointer(&event.Newname)))
		 
	case "fstatfs":
		var event constant.FstatfsData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.FstatfsFd = event.Fd
		data.FstatfsBuf = event.Buf
		 
	case "sysfs":
		var event constant.SysfsData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SysfsOption = event.Option
		data.SysfsArg1 = event.Arg1
		data.SysfsArg2 = event.Arg2
		 
	case "mincore":
		var event constant.MincoreData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.MincoreStart = event.Start
		data.MincoreLen = event.Len
		data.MincoreVec = event.Vec
		 
	case "copy_file_range":
		var event constant.CopyFileRangeData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.CopyFileRangeFdIn = event.FdIn
		data.CopyFileRangeOffIn = event.OffIn
		data.CopyFileRangeFdOut = event.FdOut
		data.CopyFileRangeOffOut = event.OffOut
		data.CopyFileRangeLen = event.Len
		data.CopyFileRangeFlags = event.Flags
		 
	case "splice":
		var event constant.SpliceData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SpliceFdIn = event.FdIn
		data.SpliceOffIn = event.OffIn
		data.SpliceFdOut = event.FdOut
		data.SpliceOffOut = event.OffOut
		data.SpliceLen = event.Len
		data.SpliceFlags = event.Flags
		 
	case "newstat":
		var event constant.NewstatData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.NewstatFilename = C.GoString((*C.char)(unsafe.Pointer(&event.Filename)))
		data.NewstatStatbuf = event.Statbuf
		 
	case "process_vm_writev":
		var event constant.ProcessVmWritevData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.ProcessVmWritevPid = event.Pid
		data.ProcessVmWritevLvec = event.Lvec
		data.ProcessVmWritevLiovcnt = event.Liovcnt
		data.ProcessVmWritevRvec = event.Rvec
		data.ProcessVmWritevRiovcnt = event.Riovcnt
		data.ProcessVmWritevFlags = event.Flags
		 
	case "timer_gettime":
		var event constant.TimerGettimeData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.TimerGettimeTimerId = event.TimerId
		data.TimerGettimeSetting = event.Setting
		 
	case "pivot_root":
		var event constant.PivotRootData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.PivotRootNewRoot = C.GoString((*C.char)(unsafe.Pointer(&event.NewRoot)))
		data.PivotRootPutOld = C.GoString((*C.char)(unsafe.Pointer(&event.PutOld)))
		 
	case "name_to_handle_at":
		var event constant.NameToHandleAtData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.NameToHandleAtDfd = event.Dfd
		data.NameToHandleAtName = C.GoString((*C.char)(unsafe.Pointer(&event.Name)))
		data.NameToHandleAtHandle = event.Handle
		data.NameToHandleAtMntId = event.MntId
		data.NameToHandleAtFlag = event.Flag
		 
	case "bind":
		var event constant.BindData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.BindFd = event.Fd
		data.BindUmyaddr = event.Umyaddr
		data.BindAddrlen = event.Addrlen
		 
	case "readlink":
		var event constant.ReadlinkData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.ReadlinkPath = C.GoString((*C.char)(unsafe.Pointer(&event.Path)))
		data.ReadlinkBuf = C.GoString((*C.char)(unsafe.Pointer(&event.Buf)))
		data.ReadlinkBufsiz = event.Bufsiz
		 
	case "getppid":
		var event constant.GetppidData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		 
	case "setuid":
		var event constant.SetuidData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SetuidUid = event.Uid
		 
	case "mremap":
		var event constant.MremapData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.MremapAddr = event.Addr
		data.MremapOldLen = event.OldLen
		data.MremapNewLen = event.NewLen
		data.MremapFlags = event.Flags
		data.MremapNewAddr = event.NewAddr
		 
	case "keyctl":
		var event constant.KeyctlData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.KeyctlOption = event.Option
		data.KeyctlArg2 = event.Arg2
		data.KeyctlArg3 = event.Arg3
		data.KeyctlArg4 = event.Arg4
		data.KeyctlArg5 = event.Arg5
		 
	case "pselect6":
		var event constant.Pselect6Data

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.Pselect6N = event.N
		data.Pselect6Inp = event.Inp
		data.Pselect6Outp = event.Outp
		data.Pselect6Exp = event.Exp
		data.Pselect6Tsp = event.Tsp
		data.Pselect6Sig = event.Sig
		 
	case "delete_module":
		var event constant.DeleteModuleData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.DeleteModuleNameUser = C.GoString((*C.char)(unsafe.Pointer(&event.NameUser)))
		data.DeleteModuleFlags = event.Flags
		 
	case "utimensat":
		var event constant.UtimensatData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.UtimensatDfd = event.Dfd
		data.UtimensatFilename = C.GoString((*C.char)(unsafe.Pointer(&event.Filename)))
		data.UtimensatUtimes = event.Utimes
		data.UtimensatFlags = event.Flags
		 
	case "get_mempolicy":
		var event constant.GetMempolicyData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.GetMempolicyPolicy = event.Policy
		data.GetMempolicyNmask = event.Nmask
		data.GetMempolicyMaxnode = event.Maxnode
		data.GetMempolicyAddr = event.Addr
		data.GetMempolicyFlags = event.Flags
		 
	case "dup":
		var event constant.DupData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.DupFildes = event.Fildes
		 
	case "eventfd":
		var event constant.EventfdData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.EventfdCount = event.Count
		 
	case "recvfrom":
		var event constant.RecvfromData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.RecvfromFd = event.Fd
		data.RecvfromUbuf = event.Ubuf
		data.RecvfromSize = event.Size
		data.RecvfromFlags = event.Flags
		data.RecvfromAddr = event.Addr
		data.RecvfromAddrLen = event.AddrLen
		 
	case "statx":
		var event constant.StatxData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.StatxDfd = event.Dfd
		data.StatxFilename = C.GoString((*C.char)(unsafe.Pointer(&event.Filename)))
		data.StatxFlags = event.Flags
		data.StatxMask = event.Mask
		data.StatxBuffer = event.Buffer
		 
	case "rt_sigaction":
		var event constant.RtSigactionData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.RtSigactionSig = event.Sig
		data.RtSigactionAct = event.Act
		data.RtSigactionOact = event.Oact
		data.RtSigactionSigsetsize = event.Sigsetsize
		 
	case "munlockall":
		var event constant.MunlockallData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		 
	case "getdents":
		var event constant.GetdentsData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.GetdentsFd = event.Fd
		data.GetdentsDirent = event.Dirent
		data.GetdentsCount = event.Count
		 
	case "epoll_create1":
		var event constant.EpollCreate1Data

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.EpollCreate1Flags = event.Flags
		 
	case "wait4":
		var event constant.Wait4Data

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.Wait4Upid = event.Upid
		data.Wait4StatAddr = event.StatAddr
		data.Wait4Options = event.Options
		data.Wait4Ru = event.Ru
		 
	case "sched_yield":
		var event constant.SchedYieldData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		 
	case "mlockall":
		var event constant.MlockallData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.MlockallFlags = event.Flags
		 
	case "sched_getattr":
		var event constant.SchedGetattrData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SchedGetattrPid = event.Pid
		data.SchedGetattrUattr = event.Uattr
		data.SchedGetattrSize = event.Size
		data.SchedGetattrFlags = event.Flags
		 
	case "setpriority":
		var event constant.SetpriorityData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SetpriorityWhich = event.Which
		data.SetpriorityWho = event.Who
		data.SetpriorityNiceval = event.Niceval
		 
	case "socket":
		var event constant.SocketData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SocketFamily = event.Family
		data.SocketType = event.Type
		data.SocketProtocol = event.Protocol
		 
	case "semtimedop":
		var event constant.SemtimedopData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SemtimedopSemid = event.Semid
		data.SemtimedopTsops = event.Tsops
		data.SemtimedopNsops = event.Nsops
		data.SemtimedopTimeout = event.Timeout
		 
	case "setfsuid":
		var event constant.SetfsuidData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SetfsuidUid = event.Uid
		 
	case "epoll_create":
		var event constant.EpollCreateData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.EpollCreateSize = event.Size
		 
	case "semop":
		var event constant.SemopData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SemopSemid = event.Semid
		data.SemopTsops = event.Tsops
		data.SemopNsops = event.Nsops
		 
	case "open":
		var event constant.OpenData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.OpenFilename = C.GoString((*C.char)(unsafe.Pointer(&event.Filename)))
		data.OpenFlags = event.Flags
		data.OpenMode = event.Mode
		 
	case "openat":
		var event constant.OpenatData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.OpenatDfd = event.Dfd
		data.OpenatFilename = C.GoString((*C.char)(unsafe.Pointer(&event.Filename)))
		data.OpenatFlags = event.Flags
		data.OpenatMode = event.Mode
		 
	case "fremovexattr":
		var event constant.FremovexattrData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.FremovexattrFd = event.Fd
		data.FremovexattrName = C.GoString((*C.char)(unsafe.Pointer(&event.Name)))
		 
	case "faccessat":
		var event constant.FaccessatData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.FaccessatDfd = event.Dfd
		data.FaccessatFilename = C.GoString((*C.char)(unsafe.Pointer(&event.Filename)))
		data.FaccessatMode = event.Mode
		 
	case "ftruncate":
		var event constant.FtruncateData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.FtruncateFd = event.Fd
		data.FtruncateLength = event.Length
		 
	case "sched_get_priority_min":
		var event constant.SchedGetPriorityMinData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SchedGetPriorityMinPolicy = event.Policy
		 
	case "move_pages":
		var event constant.MovePagesData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.MovePagesPid = event.Pid
		data.MovePagesNrPages = event.NrPages
		data.MovePagesPages = event.Pages
		data.MovePagesNodes = event.Nodes
		data.MovePagesStatus = event.Status
		data.MovePagesFlags = event.Flags
		 
	case "lseek":
		var event constant.LseekData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.LseekFd = event.Fd
		data.LseekOffset = event.Offset
		data.LseekWhence = event.Whence
		 
	case "poll":
		var event constant.PollData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.PollUfds = event.Ufds
		data.PollNfds = event.Nfds
		data.PollTimeoutMsecs = event.TimeoutMsecs
		 
	case "fdatasync":
		var event constant.FdatasyncData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.FdatasyncFd = event.Fd
		 
	case "fsync":
		var event constant.FsyncData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.FsyncFd = event.Fd
		 
	case "setsockopt":
		var event constant.SetsockoptData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SetsockoptFd = event.Fd
		data.SetsockoptLevel = event.Level
		data.SetsockoptOptname = event.Optname
		data.SetsockoptOptval = C.GoString((*C.char)(unsafe.Pointer(&event.Optval)))
		data.SetsockoptOptlen = event.Optlen
		 
	case "timer_getoverrun":
		var event constant.TimerGetoverrunData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.TimerGetoverrunTimerId = event.TimerId
		 
	case "getgid":
		var event constant.GetgidData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		 
	case "capset":
		var event constant.CapsetData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.CapsetHeader = event.Header
		data.CapsetData = event.Data
		 
	case "semget":
		var event constant.SemgetData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SemgetKey = event.Key
		data.SemgetNsems = event.Nsems
		data.SemgetSemflg = event.Semflg
		 
	case "prlimit64":
		var event constant.Prlimit64Data

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.Prlimit64Pid = event.Pid
		data.Prlimit64Resource = event.Resource
		data.Prlimit64NewRlim = event.NewRlim
		data.Prlimit64OldRlim = event.OldRlim
		 
	case "mq_unlink":
		var event constant.MqUnlinkData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.MqUnlinkUName = C.GoString((*C.char)(unsafe.Pointer(&event.UName)))
		 
	case "clock_settime":
		var event constant.ClockSettimeData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.ClockSettimeWhichClock = event.WhichClock
		data.ClockSettimeTp = event.Tp
		 
	case "rt_sigtimedwait":
		var event constant.RtSigtimedwaitData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.RtSigtimedwaitUthese = event.Uthese
		data.RtSigtimedwaitUinfo = event.Uinfo
		data.RtSigtimedwaitUts = event.Uts
		data.RtSigtimedwaitSigsetsize = event.Sigsetsize
		 
	case "sigaltstack":
		var event constant.SigaltstackData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SigaltstackUss = event.Uss
		data.SigaltstackUoss = event.Uoss
		 
	case "shmget":
		var event constant.ShmgetData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.ShmgetKey = event.Key
		data.ShmgetSize = event.Size
		data.ShmgetShmflg = event.Shmflg
		 
	case "writev":
		var event constant.WritevData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.WritevFd = event.Fd
		data.WritevVec = event.Vec
		data.WritevVlen = event.Vlen
		 
	case "mprotect":
		var event constant.MprotectData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.MprotectStart = event.Start
		data.MprotectLen = event.Len
		data.MprotectProt = event.Prot
		 
	case "setitimer":
		var event constant.SetitimerData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SetitimerWhich = event.Which
		data.SetitimerValue = event.Value
		data.SetitimerOvalue = event.Ovalue
		 
	case "remap_file_pages":
		var event constant.RemapFilePagesData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.RemapFilePagesStart = event.Start
		data.RemapFilePagesSize = event.Size
		data.RemapFilePagesProt = event.Prot
		data.RemapFilePagesPgoff = event.Pgoff
		data.RemapFilePagesFlags = event.Flags
		 
	case "getresgid":
		var event constant.GetresgidData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.GetresgidRgidp = event.Rgidp
		data.GetresgidEgidp = event.Egidp
		data.GetresgidSgidp = event.Sgidp
		 
	case "seccomp":
		var event constant.SeccompData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SeccompOp = event.Op
		data.SeccompFlags = event.Flags
		data.SeccompUargs = C.GoString((*C.char)(unsafe.Pointer(&event.Uargs)))
		 
	case "gettimeofday":
		var event constant.GettimeofdayData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.GettimeofdayTv = event.Tv
		data.GettimeofdayTz = event.Tz
		 
	case "getsockname":
		var event constant.GetsocknameData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.GetsocknameFd = event.Fd
		data.GetsocknameUsockaddr = event.Usockaddr
		data.GetsocknameUsockaddrLen = event.UsockaddrLen
		 
	case "symlinkat":
		var event constant.SymlinkatData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SymlinkatOldname = C.GoString((*C.char)(unsafe.Pointer(&event.Oldname)))
		data.SymlinkatNewdfd = event.Newdfd
		data.SymlinkatNewname = C.GoString((*C.char)(unsafe.Pointer(&event.Newname)))
		 
	case "getpid":
		var event constant.GetpidData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		 
	case "vfork":
		var event constant.VforkData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		 
	case "fork":
		var event constant.ForkData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		 
	case "getpgrp":
		var event constant.GetpgrpData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		 
	case "timer_create":
		var event constant.TimerCreateData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.TimerCreateWhichClock = event.WhichClock
		data.TimerCreateTimerEventSpec = event.TimerEventSpec
		data.TimerCreateCreatedTimerId = event.CreatedTimerId
		 
	case "listxattr":
		var event constant.ListxattrData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.ListxattrPathname = C.GoString((*C.char)(unsafe.Pointer(&event.Pathname)))
		data.ListxattrList = C.GoString((*C.char)(unsafe.Pointer(&event.List)))
		data.ListxattrSize = event.Size
		 
	case "kexec_file_load":
		var event constant.KexecFileLoadData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.KexecFileLoadKernelFd = event.KernelFd
		data.KexecFileLoadInitrdFd = event.InitrdFd
		data.KexecFileLoadCmdlineLen = event.CmdlineLen
		data.KexecFileLoadCmdlinePtr = C.GoString((*C.char)(unsafe.Pointer(&event.CmdlinePtr)))
		data.KexecFileLoadFlags = event.Flags
		 
	case "msgsnd":
		var event constant.MsgsndData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.MsgsndMsqid = event.Msqid
		data.MsgsndMsgp = event.Msgp
		data.MsgsndMsgsz = event.Msgsz
		data.MsgsndMsgflg = event.Msgflg
		 
	case "unlinkat":
		var event constant.UnlinkatData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.UnlinkatDfd = event.Dfd
		data.UnlinkatPathname = C.GoString((*C.char)(unsafe.Pointer(&event.Pathname)))
		data.UnlinkatFlag = event.Flag
		 
	case "gettid":
		var event constant.GettidData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		 
	case "execve":
		var event constant.ExecveData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.ExecveFilename = C.GoString((*C.char)(unsafe.Pointer(&event.Filename)))
		data.ExecveArgv1 = C.GoString((*C.char)(unsafe.Pointer(&event.Argv1)))
		data.ExecveArgv2 = C.GoString((*C.char)(unsafe.Pointer(&event.Argv2)))
		data.ExecveArgv3 = C.GoString((*C.char)(unsafe.Pointer(&event.Argv3)))
		data.ExecveEnvp = event.Envp
		 
	case "clone":
		var event constant.CloneData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.CloneCloneFlags = event.CloneFlags
		data.CloneNewsp = event.Newsp
		data.CloneParentTidptr = event.ParentTidptr
		data.CloneChildTidptr = event.ChildTidptr
		data.CloneTls = event.Tls
		 
	case "rseq":
		var event constant.RseqData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.RseqRseq = event.Rseq
		data.RseqRseqLen = event.RseqLen
		data.RseqFlags = event.Flags
		data.RseqSig = event.Sig
		 
	case "rt_sigreturn":
		var event constant.RtSigreturnData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		 
	case "finit_module":
		var event constant.FinitModuleData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.FinitModuleFd = event.Fd
		data.FinitModuleUargs = C.GoString((*C.char)(unsafe.Pointer(&event.Uargs)))
		data.FinitModuleFlags = event.Flags
		 
	case "pkey_free":
		var event constant.PkeyFreeData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.PkeyFreePkey = event.Pkey
		 
	case "brk":
		var event constant.BrkData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.BrkBrk = event.Brk
		 
	case "setresuid":
		var event constant.SetresuidData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SetresuidRuid = event.Ruid
		data.SetresuidEuid = event.Euid
		data.SetresuidSuid = event.Suid
		 
	case "rt_sigsuspend":
		var event constant.RtSigsuspendData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.RtSigsuspendUnewset = event.Unewset
		data.RtSigsuspendSigsetsize = event.Sigsetsize
		 
	case "lchown":
		var event constant.LchownData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.LchownFilename = C.GoString((*C.char)(unsafe.Pointer(&event.Filename)))
		data.LchownUser = event.User
		data.LchownGroup = event.Group
		 
	case "fallocate":
		var event constant.FallocateData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.FallocateFd = event.Fd
		data.FallocateMode = event.Mode
		data.FallocateOffset = event.Offset
		data.FallocateLen = event.Len
		 
	case "ioprio_set":
		var event constant.IoprioSetData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.IoprioSetWhich = event.Which
		data.IoprioSetWho = event.Who
		data.IoprioSetIoprio = event.Ioprio
		 
	case "mknodat":
		var event constant.MknodatData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.MknodatDfd = event.Dfd
		data.MknodatFilename = C.GoString((*C.char)(unsafe.Pointer(&event.Filename)))
		data.MknodatMode = event.Mode
		data.MknodatDev = event.Dev
		 
	case "pipe":
		var event constant.PipeData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.PipeFildes = event.Fildes
		data.PipeReadfd = event.ReadFd
		data.PipeWritefd = event.WriteFd
		 
	case "reboot":
		var event constant.RebootData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.RebootMagic1 = event.Magic1
		data.RebootMagic2 = event.Magic2
		data.RebootCmd = event.Cmd
		data.RebootArg = event.Arg
		 
	case "eventfd2":
		var event constant.Eventfd2Data

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.Eventfd2Count = event.Count
		data.Eventfd2Flags = event.Flags
		 
	case "unlink":
		var event constant.UnlinkData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.UnlinkPathname = C.GoString((*C.char)(unsafe.Pointer(&event.Pathname)))
		 
	case "recvmmsg":
		var event constant.RecvmmsgData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.RecvmmsgFd = event.Fd
		data.RecvmmsgMmsg = event.Mmsg
		data.RecvmmsgVlen = event.Vlen
		data.RecvmmsgFlags = event.Flags
		data.RecvmmsgTimeout = event.Timeout
		 
	case "msync":
		var event constant.MsyncData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.MsyncStart = event.Start
		data.MsyncLen = event.Len
		data.MsyncFlags = event.Flags
		 
	case "access":
		var event constant.AccessData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.AccessFilename = C.GoString((*C.char)(unsafe.Pointer(&event.Filename)))
		data.AccessMode = event.Mode
		 
	case "signalfd4":
		var event constant.Signalfd4Data

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.Signalfd4Ufd = event.Ufd
		data.Signalfd4UserMask = event.UserMask
		data.Signalfd4Sizemask = event.Sizemask
		data.Signalfd4Flags = event.Flags
		 
	case "mbind":
		var event constant.MbindData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.MbindStart = event.Start
		data.MbindLen = event.Len
		data.MbindMode = event.Mode
		data.MbindNmask = event.Nmask
		data.MbindMaxnode = event.Maxnode
		data.MbindFlags = event.Flags
		 
	case "mknod":
		var event constant.MknodData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.MknodFilename = C.GoString((*C.char)(unsafe.Pointer(&event.Filename)))
		data.MknodMode = event.Mode
		data.MknodDev = event.Dev
		 
	case "munlock":
		var event constant.MunlockData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.MunlockStart = event.Start
		data.MunlockLen = event.Len
		 
	case "getpgid":
		var event constant.GetpgidData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.GetpgidPid = event.Pid
		 
	case "getresuid":
		var event constant.GetresuidData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.GetresuidRuidp = event.Ruidp
		data.GetresuidEuidp = event.Euidp
		data.GetresuidSuidp = event.Suidp
		 
	case "fchownat":
		var event constant.FchownatData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.FchownatDfd = event.Dfd
		data.FchownatFilename = C.GoString((*C.char)(unsafe.Pointer(&event.Filename)))
		data.FchownatUser = event.User
		data.FchownatGroup = event.Group
		data.FchownatFlag = event.Flag
		 
	case "perf_event_open":
		var event constant.PerfEventOpenData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.PerfEventOpenAttrUptr = event.AttrUptr
		data.PerfEventOpenPid = event.Pid
		data.PerfEventOpenCpu = event.Cpu
		data.PerfEventOpenGroupFd = event.GroupFd
		data.PerfEventOpenFlags = event.Flags
		 
	case "newuname":
		var event constant.NewunameData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.NewunameName = event.Name
		 
	case "timerfd_create":
		var event constant.TimerfdCreateData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.TimerfdCreateClockid = event.Clockid
		data.TimerfdCreateFlags = event.Flags
		 
	case "shmdt":
		var event constant.ShmdtData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.ShmdtShmaddr = C.GoString((*C.char)(unsafe.Pointer(&event.Shmaddr)))
		 
	case "rmdir":
		var event constant.RmdirData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.RmdirPathname = C.GoString((*C.char)(unsafe.Pointer(&event.Pathname)))
		 
	case "open_by_handle_at":
		var event constant.OpenByHandleAtData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.OpenByHandleAtMountdirfd = event.Mountdirfd
		data.OpenByHandleAtHandle = event.Handle
		data.OpenByHandleAtFlags = event.Flags
		 
	case "socketpair":
		var event constant.SocketpairData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SocketpairFamily = event.Family
		data.SocketpairType = event.Type
		data.SocketpairProtocol = event.Protocol
		data.SocketpairUsockvec = event.Usockvec
		 
	case "setresgid":
		var event constant.SetresgidData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SetresgidRgid = event.Rgid
		data.SetresgidEgid = event.Egid
		data.SetresgidSgid = event.Sgid
		 
	case "getitimer":
		var event constant.GetitimerData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.GetitimerWhich = event.Which
		data.GetitimerValue = event.Value
		 
	case "mq_getsetattr":
		var event constant.MqGetsetattrData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.MqGetsetattrMqdes = event.Mqdes
		data.MqGetsetattrUMqstat = event.UMqstat
		data.MqGetsetattrUOmqstat = event.UOmqstat
		 
	case "chdir":
		var event constant.ChdirData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.ChdirFilename = C.GoString((*C.char)(unsafe.Pointer(&event.Filename)))
		 
	case "fchdir":
		var event constant.FchdirData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.FchdirFd = event.Fd
		 
	case "mmap":
		var event constant.MmapData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.MmapAddr = event.Addr
		data.MmapLen = event.Len
		data.MmapProt = event.Prot
		data.MmapFlags = event.Flags
		data.MmapFd = event.Fd
		data.MmapOff = event.Off
		 
	case "lookup_dcookie":
		var event constant.LookupDcookieData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.LookupDcookieCookie64 = event.Cookie64
		data.LookupDcookieBuf = C.GoString((*C.char)(unsafe.Pointer(&event.Buf)))
		data.LookupDcookieLen = event.Len
		 
	case "syslog":
		var event constant.SyslogData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SyslogType = event.Type
		data.SyslogBuf = C.GoString((*C.char)(unsafe.Pointer(&event.Buf)))
		data.SyslogLen = event.Len
		 
	case "accept":
		var event constant.AcceptData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.AcceptFd = event.Fd
		data.AcceptUpeerSockaddr = event.UpeerSockaddr
		data.AcceptUpeerAddrlen = event.UpeerAddrlen
		 
	case "set_mempolicy":
		var event constant.SetMempolicyData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SetMempolicyMode = event.Mode
		data.SetMempolicyNmask = event.Nmask
		data.SetMempolicyMaxnode = event.Maxnode
		 
	case "mkdirat":
		var event constant.MkdiratData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.MkdiratDfd = event.Dfd
		data.MkdiratPathname = C.GoString((*C.char)(unsafe.Pointer(&event.Pathname)))
		data.MkdiratMode = event.Mode
		 
	case "fchmodat":
		var event constant.FchmodatData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.FchmodatDfd = event.Dfd
		data.FchmodatFilename = C.GoString((*C.char)(unsafe.Pointer(&event.Filename)))
		data.FchmodatMode = event.Mode
		 
	case "mkdir":
		var event constant.MkdirData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.MkdirPathname = C.GoString((*C.char)(unsafe.Pointer(&event.Pathname)))
		data.MkdirMode = event.Mode
		 
	case "mount":
		var event constant.MountData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.MountDevName = C.GoString((*C.char)(unsafe.Pointer(&event.DevName)))
		data.MountDirName = C.GoString((*C.char)(unsafe.Pointer(&event.DirName)))
		data.MountType = C.GoString((*C.char)(unsafe.Pointer(&event.Type)))
		data.MountFlags = event.Flags
		data.MountData = event.Data
		 
	case "sched_setaffinity":
		var event constant.SchedSetaffinityData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SchedSetaffinityPid = event.Pid
		data.SchedSetaffinityLen = event.Len
		data.SchedSetaffinityUserMaskPtr = event.UserMaskPtr
		 
	case "mq_timedreceive":
		var event constant.MqTimedreceiveData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.MqTimedreceiveMqdes = event.Mqdes
		data.MqTimedreceiveUMsgPtr = C.GoString((*C.char)(unsafe.Pointer(&event.UMsgPtr)))
		data.MqTimedreceiveMsgLen = event.MsgLen
		data.MqTimedreceiveUMsgPrio = event.UMsgPrio
		data.MqTimedreceiveUAbsTimeout = event.UAbsTimeout
		 
	case "getsid":
		var event constant.GetsidData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.GetsidPid = event.Pid
		 
	case "unshare":
		var event constant.UnshareData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.UnshareUnshareFlags = event.UnshareFlags
		 
	case "capget":
		var event constant.CapgetData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.CapgetHeader = event.Header
		data.CapgetDataptr = event.Dataptr
		 
	case "linkat":
		var event constant.LinkatData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.LinkatOlddfd = event.Olddfd
		data.LinkatOldname = C.GoString((*C.char)(unsafe.Pointer(&event.Oldname)))
		data.LinkatNewdfd = event.Newdfd
		data.LinkatNewname = C.GoString((*C.char)(unsafe.Pointer(&event.Newname)))
		data.LinkatFlags = event.Flags
		 
	case "alarm":
		var event constant.AlarmData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.AlarmSeconds = event.Seconds
		 
	case "io_setup":
		var event constant.IoSetupData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.IoSetupNrEvents = event.NrEvents
		data.IoSetupCtxp = event.Ctxp
		 
	case "mq_timedsend":
		var event constant.MqTimedsendData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.MqTimedsendMqdes = event.Mqdes
		data.MqTimedsendUMsgPtr = C.GoString((*C.char)(unsafe.Pointer(&event.UMsgPtr)))
		data.MqTimedsendMsgLen = event.MsgLen
		data.MqTimedsendMsgPrio = event.MsgPrio
		data.MqTimedsendUAbsTimeout = event.UAbsTimeout
		 
	case "getcwd":
		var event constant.GetcwdData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.GetcwdBuf = C.GoString((*C.char)(unsafe.Pointer(&event.Buf)))
		data.GetcwdSize = event.Size
		 
	case "epoll_wait":
		var event constant.EpollWaitData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.EpollWaitEpfd = event.Epfd
		data.EpollWaitEvents = event.Events
		data.EpollWaitMaxevents = event.Maxevents
		data.EpollWaitTimeout = event.Timeout
		 
	case "ioperm":
		var event constant.IopermData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.IopermFrom = event.From
		data.IopermNum = event.Num
		data.IopermTurnOn = event.TurnOn
		 
	case "flock":
		var event constant.FlockData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.FlockFd = event.Fd
		data.FlockCmd = event.Cmd
		 
	case "epoll_ctl":
		var event constant.EpollCtlData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.EpollCtlEpfd = event.Epfd
		data.EpollCtlOp = event.Op
		data.EpollCtlFd = event.Fd
		data.EpollCtlEvent = event.Event
		 
	case "clock_gettime":
		var event constant.ClockGettimeData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.ClockGettimeWhichClock = event.WhichClock
		data.ClockGettimeTp = event.Tp
		 
	case "semctl":
		var event constant.SemctlData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SemctlSemid = event.Semid
		data.SemctlSemnum = event.Semnum
		data.SemctlCmd = event.Cmd
		data.SemctlArg = event.Arg
		 
	case "rt_sigprocmask":
		var event constant.RtSigprocmaskData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.RtSigprocmaskHow = event.How
		data.RtSigprocmaskNset = event.Nset
		data.RtSigprocmaskOset = event.Oset
		data.RtSigprocmaskSigsetsize = event.Sigsetsize
		 
	case "personality":
		var event constant.PersonalityData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.PersonalityPersonality = event.Personality
		 
	case "llistxattr":
		var event constant.LlistxattrData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.LlistxattrPathname = C.GoString((*C.char)(unsafe.Pointer(&event.Pathname)))
		data.LlistxattrList = C.GoString((*C.char)(unsafe.Pointer(&event.List)))
		data.LlistxattrSize = event.Size
		 
	case "ptrace":
		var event constant.PtraceData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.PtraceRequest = event.Request
		data.PtracePid = event.Pid
		data.PtraceAddr = event.Addr
		data.PtraceData = event.Data
		 
	case "setdomainname":
		var event constant.SetdomainnameData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SetdomainnameName = C.GoString((*C.char)(unsafe.Pointer(&event.Name)))
		data.SetdomainnameLen = event.Len
		 
	case "process_vm_readv":
		var event constant.ProcessVmReadvData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.ProcessVmReadvPid = event.Pid
		data.ProcessVmReadvLvec = event.Lvec
		data.ProcessVmReadvLiovcnt = event.Liovcnt
		data.ProcessVmReadvRvec = event.Rvec
		data.ProcessVmReadvRiovcnt = event.Riovcnt
		data.ProcessVmReadvFlags = event.Flags
		 
	case "vhangup":
		var event constant.VhangupData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		 
	case "arch_prctl":
		var event constant.ArchPrctlData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.ArchPrctlOption = event.Option
		data.ArchPrctlArg2 = event.Arg2
		 
	case "recvmsg":
		var event constant.RecvmsgData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.RecvmsgFd = event.Fd
		data.RecvmsgMsg = event.Msg
		data.RecvmsgFlags = event.Flags
		 
	case "nanosleep":
		var event constant.NanosleepData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.NanosleepRqtp = event.Rqtp
		data.NanosleepRmtp = event.Rmtp
		 
	case "fcntl":
		var event constant.FcntlData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.FcntlFd = event.Fd
		data.FcntlCmd = event.Cmd
		data.FcntlArg = event.Arg
		 
	case "io_cancel":
		var event constant.IoCancelData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.IoCancelCtxId = event.CtxId
		data.IoCancelIocb = event.Iocb
		data.IoCancelResult = event.Result
		 
	case "getdents64":
		var event constant.Getdents64Data

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.Getdents64Fd = event.Fd
		data.Getdents64Dirent = event.Dirent
		data.Getdents64Count = event.Count
		 
	case "inotify_rm_watch":
		var event constant.InotifyRmWatchData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.InotifyRmWatchFd = event.Fd
		data.InotifyRmWatchWd = event.Wd
		 
	case "flistxattr":
		var event constant.FlistxattrData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.FlistxattrFd = event.Fd
		data.FlistxattrList = C.GoString((*C.char)(unsafe.Pointer(&event.List)))
		data.FlistxattrSize = event.Size
		 
	case "read":
		var event constant.ReadData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.ReadFd = event.Fd
		data.ReadBuf = C.GoString((*C.char)(unsafe.Pointer(&event.Buf)))
		data.ReadCount = event.Count
		 
	case "clock_nanosleep":
		var event constant.ClockNanosleepData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.ClockNanosleepWhichClock = event.WhichClock
		data.ClockNanosleepFlags = event.Flags
		data.ClockNanosleepRqtp = event.Rqtp
		data.ClockNanosleepRmtp = event.Rmtp
		 
	case "sysctl":
		var event constant.SysctlData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SysctlArgs = event.Args
		 
	case "chown":
		var event constant.ChownData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.ChownFilename = C.GoString((*C.char)(unsafe.Pointer(&event.Filename)))
		data.ChownUser = event.User
		data.ChownGroup = event.Group
		 
	case "setgroups":
		var event constant.SetgroupsData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SetgroupsGidsetsize = event.Gidsetsize
		data.SetgroupsGrouplist = event.Grouplist
		 
	case "newfstat":
		var event constant.NewfstatData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.NewfstatFd = event.Fd
		data.NewfstatStatbuf = event.Statbuf
		 
	case "madvise":
		var event constant.MadviseData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.MadviseStart = event.Start
		data.MadviseLenIn = event.LenIn
		data.MadviseBehavior = event.Behavior
		 
	case "fchown":
		var event constant.FchownData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.FchownFd = event.Fd
		data.FchownUser = event.User
		data.FchownGroup = event.Group
		 
	case "inotify_init1":
		var event constant.InotifyInit1Data

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.InotifyInit1Flags = event.Flags
		 
	case "add_key":
		var event constant.AddKeyData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.AddKeyType = C.GoString((*C.char)(unsafe.Pointer(&event.Type)))
		data.AddKeyDescription = C.GoString((*C.char)(unsafe.Pointer(&event.Description)))
		data.AddKeyPayload = event.Payload
		data.AddKeyPlen = event.Plen
		data.AddKeyRingid = event.Ringid
		 
	case "memfd_create":
		var event constant.MemfdCreateData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.MemfdCreateUname = C.GoString((*C.char)(unsafe.Pointer(&event.Uname)))
		data.MemfdCreateFlags = event.Flags
		 
	case "mq_open":
		var event constant.MqOpenData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.MqOpenUName = C.GoString((*C.char)(unsafe.Pointer(&event.UName)))
		data.MqOpenOflag = event.Oflag
		data.MqOpenMode = event.Mode
		data.MqOpenUAttr = event.UAttr
		 
	case "init_module":
		var event constant.InitModuleData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.InitModuleUmod = event.Umod
		data.InitModuleLen = event.Len
		data.InitModuleUargs = C.GoString((*C.char)(unsafe.Pointer(&event.Uargs)))
		 
	case "sched_setattr":
		var event constant.SchedSetattrData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SchedSetattrPid = event.Pid
		data.SchedSetattrUattr = event.Uattr
		data.SchedSetattrFlags = event.Flags
		 
	case "restart_syscall":
		var event constant.RestartSyscallData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		 
	case "ioctl":
		var event constant.IoctlData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.IoctlFd = event.Fd
		data.IoctlCmd = event.Cmd
		data.IoctlArg = event.Arg
		 
	case "request_key":
		var event constant.RequestKeyData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.RequestKeyType = C.GoString((*C.char)(unsafe.Pointer(&event.Type)))
		data.RequestKeyDescription = C.GoString((*C.char)(unsafe.Pointer(&event.Description)))
		data.RequestKeyCalloutInfo = C.GoString((*C.char)(unsafe.Pointer(&event.CalloutInfo)))
		data.RequestKeyDestringid = event.Destringid
		 
	case "inotify_init":
		var event constant.InotifyInitData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		 
	case "umount":
		var event constant.UmountData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.UmountName = C.GoString((*C.char)(unsafe.Pointer(&event.Name)))
		data.UmountFlags = event.Flags
		 
	case "preadv":
		var event constant.PreadvData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.PreadvFd = event.Fd
		data.PreadvVec = event.Vec
		data.PreadvVlen = event.Vlen
		data.PreadvPosL = event.PosL
		data.PreadvPosH = event.PosH
		 
	case "vmsplice":
		var event constant.VmspliceData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.VmspliceFd = event.Fd
		data.VmspliceUiov = event.Uiov
		data.VmspliceNrSegs = event.NrSegs
		data.VmspliceFlags = event.Flags
		 
	case "sysinfo":
		var event constant.SysinfoData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SysinfoInfo = event.Info
		 
	case "timer_settime":
		var event constant.TimerSettimeData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.TimerSettimeTimerId = event.TimerId
		data.TimerSettimeFlags = event.Flags
		data.TimerSettimeNewSetting = event.NewSetting
		data.TimerSettimeOldSetting = event.OldSetting
		 
	case "quotactl":
		var event constant.QuotactlData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.QuotactlCmd = event.Cmd
		data.QuotactlSpecial = C.GoString((*C.char)(unsafe.Pointer(&event.Special)))
		data.QuotactlId = event.Id
		data.QuotactlAddr = event.Addr
		 
	case "getgroups":
		var event constant.GetgroupsData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.GetgroupsGidsetsize = event.Gidsetsize
		data.GetgroupsGrouplist = event.Grouplist
		 
	case "fchmod":
		var event constant.FchmodData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.FchmodFd = event.Fd
		data.FchmodMode = event.Mode
		 
	case "fadvise64":
		var event constant.Fadvise64Data

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.Fadvise64Fd = event.Fd
		data.Fadvise64Offset = event.Offset
		data.Fadvise64Len = event.Len
		data.Fadvise64Advice = event.Advice
		 
	case "io_submit":
		var event constant.IoSubmitData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.IoSubmitCtxId = event.CtxId
		data.IoSubmitNr = event.Nr
		data.IoSubmitIocbpp = event.Iocbpp
		 
	case "chmod":
		var event constant.ChmodData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.ChmodFilename = C.GoString((*C.char)(unsafe.Pointer(&event.Filename)))
		data.ChmodMode = event.Mode
		 
	case "pwrite64":
		var event constant.Pwrite64Data

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.Pwrite64Fd = event.Fd
		data.Pwrite64Buf = C.GoString((*C.char)(unsafe.Pointer(&event.Buf)))
		data.Pwrite64Count = event.Count
		data.Pwrite64Pos = event.Pos
		 
	case "settimeofday":
		var event constant.SettimeofdayData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SettimeofdayTv = event.Tv
		data.SettimeofdayTz = event.Tz
		 
	case "sched_getparam":
		var event constant.SchedGetparamData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SchedGetparamPid = event.Pid
		data.SchedGetparamParam = event.Param
		 
	case "sched_getaffinity":
		var event constant.SchedGetaffinityData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SchedGetaffinityPid = event.Pid
		data.SchedGetaffinityLen = event.Len
		data.SchedGetaffinityUserMaskPtr = event.UserMaskPtr
		 
	case "msgctl":
		var event constant.MsgctlData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.MsgctlMsqid = event.Msqid
		data.MsgctlCmd = event.Cmd
		data.MsgctlBuf = event.Buf
		 
	case "timerfd_settime":
		var event constant.TimerfdSettimeData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.TimerfdSettimeUfd = event.Ufd
		data.TimerfdSettimeFlags = event.Flags
		data.TimerfdSettimeUtmr = event.Utmr
		data.TimerfdSettimeOtmr = event.Otmr
		 
	case "setsid":
		var event constant.SetsidData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		 
	case "connect":
		var event constant.ConnectData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.ConnectFd = event.Fd
		data.ConnectUservaddr = event.Uservaddr
		data.ConnectAddrlen = event.Addrlen
		 
	case "sendto":
		var event constant.SendtoData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SendtoFd = event.Fd
		data.SendtoBuff = event.Buff
		data.SendtoLen = event.Len
		data.SendtoFlags = event.Flags
		data.SendtoAddr = event.Addr
		data.SendtoAddrLen = event.AddrLen
		 
	case "bpf":
		var event constant.BpfData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.BpfCmd = event.Cmd
		data.BpfUattr = event.Uattr
		data.BpfSize = event.Size
		 
	case "kcmp":
		var event constant.KcmpData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.KcmpPid1 = event.Pid1
		data.KcmpPid2 = event.Pid2
		data.KcmpType = event.Type
		data.KcmpIdx1 = event.Idx1
		data.KcmpIdx2 = event.Idx2
		 
	case "mlock2":
		var event constant.Mlock2Data

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.Mlock2Start = event.Start
		data.Mlock2Len = event.Len
		data.Mlock2Flags = event.Flags
		 
	case "pwritev2":
		var event constant.Pwritev2Data

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.Pwritev2Fd = event.Fd
		data.Pwritev2Vec = event.Vec
		data.Pwritev2Vlen = event.Vlen
		data.Pwritev2PosL = event.PosL
		data.Pwritev2PosH = event.PosH
		data.Pwritev2Flags = event.Flags
		 
	case "sched_setparam":
		var event constant.SchedSetparamData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SchedSetparamPid = event.Pid
		data.SchedSetparamParam = event.Param
		 
	case "swapoff":
		var event constant.SwapoffData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SwapoffSpecialfile = C.GoString((*C.char)(unsafe.Pointer(&event.Specialfile)))
		 
	case "userfaultfd":
		var event constant.UserfaultfdData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.UserfaultfdFlags = event.Flags
		 
	case "io_pgetevents":
		var event constant.IoPgeteventsData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.IoPgeteventsCtxId = event.CtxId
		data.IoPgeteventsMinNr = event.MinNr
		data.IoPgeteventsNr = event.Nr
		data.IoPgeteventsEvents = event.Events
		data.IoPgeteventsTimeout = event.Timeout
		data.IoPgeteventsUsig = event.Usig
		 
	case "listen":
		var event constant.ListenData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.ListenFd = event.Fd
		data.ListenBacklog = event.Backlog
		 
	case "get_robust_list":
		var event constant.GetRobustListData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.GetRobustListPid = event.Pid
		data.GetRobustListHeadPtr = event.HeadPtr
		data.GetRobustListLenPtr = event.LenPtr
		 
	case "setns":
		var event constant.SetnsData

		err := binary.Read(bytes.NewBuffer(byteData), binary.LittleEndian, &event)
		if err != nil {
			err := fmt.Errorf("Failed to decode received data: %s\n", err)
			return nil, err
		}
		data.EventInfo = event.EventInfo
		data.IsSyscall = true
		data.SetnsFd = event.Fd
		data.SetnsNstype = event.Nstype
		 
	}
	return &data, nil
}
