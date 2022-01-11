package main

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"runtime/debug"

	json "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/setns/setnsmnt"
	"gitlab.com/piccolo_su/vegeta/pkg/daemon"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	_ "go.uber.org/automaxprocs"
	"golang.org/x/sys/unix"
)

var filename *os.File

const (
	BasePath     = "/host"
	unixSockFile = "/tmp/setns.sock"
)

func init() {
	//log.SetLevel(log.InfoLevel)
}

func UnshareInit() error {
	err := unix.Unshare(unix.CLONE_NEWNS)
	if err != nil {
		return errors.Errorf("unix unshare failed, %v", err)
	}

	return nil
}

func GetComm(pid int) string {
	path := fmt.Sprintf("%s/proc/%v/comm", BasePath, pid)
	data, err := ioutil.ReadFile(path)
	if err != nil {
		logging.GetLogger().Error().Msgf("read data failed, %v, %v.", path, err)
		return "-"
	}

	comm := string(data)
	return comm[:len(comm)-1]
}

func SetNs(pid int) error {
	path := fmt.Sprintf("%s/proc/%v/ns/mnt", BasePath, pid)
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return errors.Errorf("open %s failed, %v", path, err)
	}
	//close file handle
	defer f.Close()

	err = unix.Setns(int(f.Fd()), 0)
	if err != nil {
		return errors.Errorf("setns failed with path : %s, %v", path, err)
	}

	return nil
}

func GetProcessName(mnt *daemon.PidAssociateMnt) (string, error) {

	err := SetNs(mnt.Pid)
	if err != nil {
		return "", errors.Errorf("set ns failed, pid : %v, %v", mnt.Pid, err)
	}

	switch mnt.TupleInfo.Proto {
	case unix.IPPROTO_TCP:
		return setnsmnt.GetProcessWithTcp(mnt.Pid, mnt.AddrType, &mnt.TupleInfo)
	case unix.IPPROTO_UDP:
		return setnsmnt.GetProcessWithUdp(mnt.Pid, mnt.AddrType, &mnt.TupleInfo)
	default:
	}

	return "", nil
}

func OpenLocalMnt() error {
	err := UnshareInit()
	if err != nil {
		return errors.Errorf("unshare failed, %v", err)
	}

	path := "/proc/1/ns/mnt"
	filename, err = os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return errors.Errorf("open local file failed, %v", err)
	}
	return nil
}
func SetLocalNs(f *os.File) error {
	err := unix.Setns(int(f.Fd()), 0)
	if err != nil {
		return errors.Errorf("set local mnt ns failed, %v", err)
	}
	return nil
}

func SendResponse(data *daemon.ProcessInfo, client net.Conn) error {
	//json marshal
	ret, err := json.Marshal(data)
	if err != nil {
		return errors.Errorf("json marshal failed, %v", err)
	}
	//send response data
	_, err = client.Write(ret)
	if err != nil {
		return errors.Errorf("write to udp failed, %v\n", err)
	}

	return nil
}

func CreateUnixSocket() (*net.UnixListener, error) {
	//remove unix socket file
	os.Remove(unixSockFile)
	addr, err := net.ResolveUnixAddr("unix", unixSockFile)
	if err != nil {
		return nil, errors.Errorf("create unix socket failed, %v", err)
	}
	//listen
	server, err := net.ListenUnix("unix", addr)
	if err != nil {
		return nil, errors.Errorf("unix socket listen failed, %v", err)
	}
	//return
	return server, nil
}

func ProcessRcvData(client net.Conn) {
	//process data
	for {
		rsp := daemon.ProcessInfo{
			Pid:      0,
			ProcName: "-",
		}

		var name string
		var pidMnt daemon.PidAssociateMnt
		var dataBuf [1024]byte
		//read udp data
		length, err := client.Read(dataBuf[:])
		if err != nil {
			logging.GetLogger().Error().Msgf("read udp data failed, %v.", err)
			continue
		}
		//json
		err = json.Unmarshal(dataBuf[:length], &pidMnt)
		if err != nil || pidMnt.Pid <= 0 {
			if err != nil {
				logging.GetLogger().Error().Msgf("json unmarshal failed, %v.", err)
			} else {
				logging.GetLogger().Error().Msgf("pid is error, pid : %v.", pidMnt.Pid)
			}
			//send response data
			err = SendResponse(&rsp, client)
			if err != nil {
				logging.GetLogger().Error().Msgf("send response failed, %v.", err)
			}
			continue
		}
		//get process name by comm
		comm := GetComm(pidMnt.Pid)
		//get process name by set mnt
		name, err = GetProcessName(&pidMnt)
		if err != nil {
			logging.GetLogger().Error().Msgf("get process name failed, %s, comm : %v, %v.", string(dataBuf[:length]), comm, err)
		}

		if len(name) == 0 || name == "-" {
			name = comm
		}
		//fill value
		rsp.Pid = pidMnt.Pid
		rsp.ProcName = name
		//send response data
		err = SendResponse(&rsp, client)
		if err != nil {
			logging.GetLogger().Error().Msgf("send response failed, %v", err)
		}
		//Unshare
		err = UnshareInit()
		if err != nil {
			logging.GetLogger().Error().Msgf("unshare failed, %v", err)
		}
		//set local mnt
		err = SetLocalNs(filename)
		if err != nil {
			logging.GetLogger().Error().Msgf("set local ns failed, %v", err)
		}
	}
}

func main() {
	unixSvr, err := CreateUnixSocket()
	if err != nil {
		logging.GetLogger().Error().Msgf("create unix server failed, %v", err)
		os.Exit(1)
	}
	//defer
	defer func() {
		_ = unixSvr.Close()
		os.Exit(1)
	}()
	//open local mnt
	err = OpenLocalMnt()
	if err != nil {
		logging.GetLogger().Error().Msgf("open local mnt failed, %v", err)
		return
	}
	//accept
	for {
		fd, err := unixSvr.Accept()
		if err != nil {
			logging.GetLogger().Error().Msgf("unix socket accept error, %v", err)
			continue
		}
		//process data
		go func(client net.Conn) {
			defer func() {
				if r := recover(); r != nil {
					logging.GetLogger().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
				}
			}()
			//process data
			ProcessRcvData(client)
		}(fd)
	}
}
