package main

import (
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/setns/setnsmnt"
	"gitlab.com/piccolo_su/vegeta/pkg/daemon"
	"golang.org/x/sys/unix"
	"io/ioutil"
	"net"
	"os"
)

var filename *os.File

const BasePath = "/host"

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
		fmt.Printf("read data failed, %v, %v\n", path, err)
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

func SendResponse(data *daemon.ProcessInfo, udpConn *net.UDPConn, addr *net.UDPAddr) error {
	//json marshal
	ret, err := json.Marshal(data)
	if err != nil {
		return errors.Errorf("json marshal failed, %v", err)
	}
	//send response data
	_, err = udpConn.WriteToUDP(ret, addr)
	if err != nil {
		return errors.Errorf("write to udp failed, %v\n", err)
	}

	return nil
}

func main() {
	err := OpenLocalMnt()
	if err != nil {
		fmt.Printf("open local mnt failed, %v\n", err)
		return
	}

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.IPv4(0, 0, 0, 0),
		Port: 59090,
	})

	if err != nil {
		fmt.Printf("listen udp failed, %v\n", err)
		return
	}

	for {
		rsp := daemon.ProcessInfo{
			Pid:      0,
			ProcName: "",
		}
		var dataBuf [1024]byte
		length, addr, err := udpConn.ReadFromUDP(dataBuf[:])
		if err != nil {
			fmt.Printf("read udp data failed, %v\n", err)
			continue
		}
		//
		var pidMnt daemon.PidAssociateMnt
		//fmt.Printf("%v\n", string(dataBuf[:length]))
		//json
		err = json.Unmarshal(dataBuf[:length], &pidMnt)
		if err != nil {
			fmt.Printf("json unmarshal failed, %v\n", err)
			err = SendResponse(&rsp, udpConn, addr)
			if err != nil {
				fmt.Printf("send response failed, %v\n", err)
			}
			continue
		}
		comm := GetComm(pidMnt.Pid)
		//
		name, err := GetProcessName(&pidMnt)
		if err != nil {
			fmt.Printf("get process name failed, %s, %v\n", string(dataBuf[:length]), err)
		}

		if len(name) == 0 || name == "-" {
			name = comm
		}

		rsp.Pid = pidMnt.Pid
		rsp.ProcName = name

		err = SendResponse(&rsp, udpConn, addr)
		if err != nil {
			fmt.Printf("send response failed, %v\n", err)
		}

		err = UnshareInit()
		if err != nil {
			fmt.Printf("unshare failed, %v\n", err)
		}

		err = SetLocalNs(filename)
		if err != nil {
			fmt.Errorf("set local ns failed, %v", err)
		}
	}
}
