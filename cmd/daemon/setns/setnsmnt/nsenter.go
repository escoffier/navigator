package setnsmnt

import (
	"fmt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gitlab.com/piccolo_su/vegeta/pkg/daemon"
	"golang.org/x/sys/unix"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

var STATE = map[string]string{
	"01": "ESTABLISHED",
	"02": "SYN_SENT",
	"03": "SYN_RECV",
	"04": "FIN_WAIT1",
	"05": "FIN_WAIT2",
	"06": "TIME_WAIT",
	"07": "CLOSE",
	"08": "CLOSE_WAIT",
	"09": "LAST_ACK",
	"0A": "LISTEN",
	"0B": "CLOSING",
}

func HexToDec(h string) int64 {
	// convert hexadecimal to decimal.
	d, err := strconv.ParseInt(h, 16, 32)
	if err != nil {
		return 0
	}

	return d
}
func RemoveSpace(array []string) []string {
	// remove empty data from line
	var newArr []string

	for _, i := range array {
		if i != "" {
			newArr = append(newArr, i)
		}
	}

	return newArr
}

func ReadNetData(path string) ([]string, error) {

	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, errors.Errorf("readfile %v failed, %v", path, err)
	}

	lines := strings.Split(string(data), "\n")

	// Return lines without Header line and blank line on the end
	return lines[1 : len(lines)-1], nil
}

func convertIp(ip string) string {
	// Convert the ipv4 to decimal. Have to rearrange the ip because the
	// default value is in little Endian order.

	var out string

	// Check ip size if greater than 8 is a ipv6 type
	if len(ip) > 8 {
		i := []string{ip[30:32],
			ip[28:30],
			ip[26:28],
			ip[24:26],
			ip[22:24],
			ip[20:22],
			ip[18:20],
			ip[16:18],
			ip[14:16],
			ip[12:14],
			ip[10:12],
			ip[8:10],
			ip[6:8],
			ip[4:6],
			ip[2:4],
			ip[0:2]}
		out = fmt.Sprintf("%v%v:%v%v:%v%v:%v%v:%v%v:%v%v:%v%v:%v%v",
			i[14], i[15], i[13], i[12],
			i[10], i[11], i[8], i[9],
			i[6], i[7], i[4], i[5],
			i[2], i[3], i[0], i[1])

	} else {
		i := []int64{HexToDec(ip[6:8]),
			HexToDec(ip[4:6]),
			HexToDec(ip[2:4]),
			HexToDec(ip[0:2])}

		out = fmt.Sprintf("%v.%v.%v.%v", i[0], i[1], i[2], i[3])
	}
	return out
}

func GetProcessCommand(pid string) string {
	if len(pid) == 0 {
		return ""
	}
	exe := fmt.Sprintf("/proc/%s/comm", pid)
	data, err := ioutil.ReadFile(exe)
	if err != nil {
		return ""
	}

	comm := string(data)
	return comm[:len(comm)-1]
}

func GetUser(uid string) string {
	u, err := user.LookupId(uid)
	if err != nil {
		return "Unknown"
	}
	return u.Username
}

func GetAllInodes() (map[string]string, error) {

	fileDes, err := filepath.Glob("/proc/[0-9]*/fd/[0-9]*")
	if err != nil {
		return nil, errors.Errorf("get all file descriptors failed, %v", err)
	}

	inodes := make(map[string]string, 0)

	for _, item := range fileDes {
		link, _ := os.Readlink(item)
		ok := strings.Contains(link, "socket:[")
		if !ok {
			continue
		}

		inodes[link] = item
	}

	return inodes, nil
}

func FilterSocketInode(inode string) (string, error) {

	fileDes, err := filepath.Glob("/proc/[0-9]*/fd/[0-9]*")
	if err != nil {
		return "", errors.Errorf("get all file descriptors failed, %v", err)
	}

	for _, item := range fileDes {
		link, _ := os.Readlink(item)
		if link == inode {
			return item, nil
		}
	}

	return "", errors.Errorf("can not find socket by inode %v", inode)
}

func GetPidByInode(inode string) string {

	path, err := FilterSocketInode(fmt.Sprintf("socket:[%s]", inode))
	if err != nil {
		log.Errorf("get all inode failed! %v.", err)
		return ""
	}

	values := strings.Split(path, "/")
	return values[2]
}

func GetNetFile(proto uint8, pid int) ([]string, error) {
	procpath := fmt.Sprintf("/proc/[0-9]*")
	procs, err := filepath.Glob(procpath)
	if err != nil {
		return nil, errors.Errorf("get process id files failed, pid : %v, %v", pid, err)
	}
	//
	files := make([]string, 0)
	//list file
	for _, path := range procs {
		switch proto {
		case unix.IPPROTO_TCP:
			files = append(files, fmt.Sprintf("%s/net/tcp", path))
			files = append(files, fmt.Sprintf("%s/net/tcp6", path))
		case unix.IPPROTO_UDP:
			files = append(files, fmt.Sprintf("%s/net/udp", path))
			files = append(files, fmt.Sprintf("%s/net/udp6", path))
		default:
		}
	}

	if len(files) > 10 {
		return nil, errors.Errorf("process number : %v, this number is error, pid : %v", len(files), pid)
	}

	return files, nil
}

func GetProcessWithTcp(pid int, addrType uint8, addr *daemon.FiveTuple) (string, error) {

	paths, err := GetNetFile(addr.Proto, pid)
	if err != nil {
		//return "-", errors.Errorf("get net file failed, %v", err)
		return "", nil
	}

	for _, path := range paths {
		data, err := ReadNetData(path)
		if err != nil {
			return "", errors.Errorf("read tcp net file failed, pid : %v, %v", pid, err)
		}

		for _, line := range data {

			netInfos := RemoveSpace(strings.Split(strings.TrimSpace(line), " "))
			local := strings.Split(netInfos[1], ":")
			localIp := convertIp(local[0])
			localPort := HexToDec(local[1])

			// foreign ip and port
			//remote := strings.Split(netInfos[2], ":")
			//foreignIp := convertIp(remote[0])
			//foreignPort := HexToDec(remote[1])

			state := netInfos[3]
			if state != "0A" && state != "01" {
				continue
			}

			switch addrType {
			case daemon.RCV_ADDR:
				if localPort != int64(addr.DstPort) {
					continue
				}
				cpid := GetPidByInode(netInfos[9])

				return GetProcessCommand(cpid), nil

			case daemon.SND_ADDR:
				if localIp != addr.SrcIp || localPort != int64(addr.SrcPort) {
					continue
				}

				//get pid by inode
				cpid := GetPidByInode(netInfos[9])

				return GetProcessCommand(cpid), nil
			default:

			}
		}
	}

	return "", errors.Errorf("can not match this address")
}

func GetProcessWithUdp(pid int, addrType uint8, addr *daemon.FiveTuple) (string, error) {
	paths, err := GetNetFile(addr.Proto, pid)
	if err != nil {
		return "", errors.Errorf("get udp net file failed, pid : %v, %v", pid, err)
	}

	for _, path := range paths {
		data, err := ReadNetData(path)
		if err != nil {
			return "", errors.Errorf("read net file failed, %v", err)
		}

		for _, line := range data {

			netInfos := RemoveSpace(strings.Split(strings.TrimSpace(line), " "))
			local := strings.Split(netInfos[1], ":")
			localIp := convertIp(local[0])
			localPort := HexToDec(local[1])

			// foreign ip and port
			remote := strings.Split(netInfos[2], ":")
			foreignIp := convertIp(remote[0])
			foreignPort := HexToDec(remote[1])

			if addrType == daemon.SND_ADDR {
				if localIp != addr.SrcIp || localPort != int64(addr.SrcPort) {
					continue
				}
			} else {
				if foreignIp != addr.SrcIp || foreignPort != int64(addr.SrcPort) {
					continue
				}
			}
			//get pid by inode
			cpid := GetPidByInode(netInfos[9])

			return GetProcessCommand(cpid), nil
		}
	}

	return "", errors.Errorf("can not match this address")
}
