package nodeinfo

import (
	"fmt"
	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/pkg/daemon"
	"gitlab.com/security-rd/go-pkg/logging"
	"io/ioutil"
	"os"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func GetProcessPid(pid int, basePath string) ([]int, error) {
	cPids := make([]int, 0)
	//
	cPids = append(cPids, pid)
	//check pid
	if pid <= 0 {
		return nil, errors.Errorf("please input correct pid")
	}
	//path
	path := fmt.Sprintf("%v/proc/%v/task/%v/children", basePath, pid, pid)
	//read data
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, errors.Errorf("read data form %v failed, %v", path, err)
	}
	//
	if len(data) == 0 {
		return cPids, nil
	}
	//get sub pid
	value := strings.Split(string(data), " ")
	for _, v := range value {
		if len(v) == 0 {
			continue
		}
		//string to int
		subPid, err := strconv.Atoi(v)
		if err != nil {
			logging.Get().Error().Msgf("convert string to int failed.")
			continue
		}
		ret, err := GetProcessPid(subPid, basePath)
		if err != nil {
			logging.Get().Error().Msgf("get process id failed, %+v.", err)
			continue
		}
		cPids = append(cPids, ret...)
	}
	//
	return cPids, nil
}

func GetProcessStartTime() func(int, string) (string, error) {
	sys := &syscall.Sysinfo_t{}
	err := syscall.Sysinfo(sys)
	if err != nil {
		logging.Get().Error().Msgf("get boot time failed, %+v.", err)
		return nil
	}
	uptime := time.Now().Unix() - sys.Uptime
	//get process time
	return func(pid int, basePath string) (string, error) {
		path := fmt.Sprintf("%v/proc/%d/stat", basePath, pid)
		buf, err := ioutil.ReadFile(path)
		if err != nil {
			return "", errors.Errorf("read data from %v failed, %+v", path, err)
		}
		fields := strings.Fields(string(buf))
		if len(fields) <= 22 {
			return "", errors.Errorf("%v data error")
		}
		start, err := strconv.ParseInt(fields[21], 10, 0)
		if err != nil {
			return "", errors.Errorf("parse %v failed, %+v", fields[21], err)
		}
		return time.Unix(uptime+(start/100), 0).Format("2006-01-02 15:04:05"), nil
	}
}

func GetProcessName(pid int, basePath string) (string, error) {
	path := fmt.Sprintf("%v/proc/%v/comm", basePath, pid)
	buf, err := ioutil.ReadFile(path)
	if err != nil {
		return "", errors.Errorf("read data from %v failed, %+v", path, err)
	}
	//delete invalid char
	value := strings.ReplaceAll(string(buf), "\n", "")
	return value, nil
}

func GetProcessUser(pid int, basePath string) (string, error) {
	path := fmt.Sprintf("%v/proc/%v/status", basePath, pid)
	buf, err := ioutil.ReadFile(path)
	if err != nil {
		return "", errors.Errorf("read data from %v failed, %+v", path, err)
	}
	//get uid
	lines := strings.Split(string(buf), "\n")
	//index
	i := 0
	status := false
	//parse
	for i = 0; i < len(lines); i++ {
		ret := strings.Index(lines[i], "Uid:")
		if ret < 0 {
			continue
		}
		status = true
		break
	}
	//check
	if !status {
		return "", errors.Errorf("pase %v's data failed")
	}
	//get uid
	fields := strings.Fields(lines[i])
	if len(fields) < 2 {
		return "", errors.Errorf("pase uid data failed, %v", lines[i])
	}
	//get user
	data, err := user.LookupId(fields[1])
	if err != nil {
		return fields[1], nil
	}
	//print debug log
	//fmt.Printf("process user : %+v\n", *data)
	return data.Username, nil
}

func GetHostIpAddr() (string, error) {
	hostIp := os.Getenv("MY_HOST_IP")
	if len(hostIp) == 0 {
		return "", errors.Errorf("get host ip failed")
	}
	return hostIp, nil
}

func GetListenPort(pid int, basePath string) ([]*daemon.ListenPort, error) {
	if pid <= 0 {
		return nil, errors.Errorf("pid is error")
	}

	hostIp, err := GetHostIpAddr()
	if err != nil {
		return nil, err
	}
	//net file
	paths := []string{
		fmt.Sprintf("%v/proc/%v/net/tcp", basePath, pid),
		fmt.Sprintf("%v/proc/%v/net/tcp6", basePath, pid),
		fmt.Sprintf("%v/proc/%v/net/udp", basePath, pid),
		fmt.Sprintf("%v/proc/%v/net/udp6", basePath, pid),
	}
	result := make([]*daemon.ListenPort, 0)
	rePort := make(map[string]struct{}, 0)
	//read file
	for i := 0; i < len(paths); i++ {
		buf, err := ioutil.ReadFile(paths[i])
		if err != nil {
			logging.Get().Error().Msgf("read data from %v failed, %+v.", paths[i], err)
			continue
		}
		//get lines
		lines := strings.Split(string(buf), "\n")
		for line := 1; line < len(lines); line++ {
			if len(lines[line]) < 20 {
				continue
			}

			fields := strings.Fields(lines[line])
			if len(fields) < 4 {
				logging.Get().Error().Msgf("pase net link data failed, %v.", lines[i])
				continue
			}
			localAddr := fields[1]
			remoteAddr := fields[2]
			laddr := strings.Split(localAddr, ":")
			raddr := strings.Split(remoteAddr, ":")
			if len(laddr) != 2 || len(raddr) != 2 {
				logging.Get().Error().Msgf("pase address data failed, local address : %v, remote address : %v.", localAddr, remoteAddr)
				continue
			}
			rport, err := strconv.ParseInt(raddr[1], 16, 32)
			if err != nil {
				logging.Get().Error().Msgf("convert remote port failed, local port : %v, err : %v.", raddr[1], err)
				continue
			}
			if rport != 0 {
				break
			}
			lport, err := strconv.ParseInt(laddr[1], 16, 32)
			if err != nil {
				logging.Get().Error().Msgf("convert local port failed, local port : %v, err : %v.", laddr[1], err)
				continue
			}
			proto := "tcp"
			if i >= 2 {
				proto = "udp"
			}
			//filter repeat port
			key := fmt.Sprintf("%v-%v", lport, proto)
			_, ok := rePort[key]
			if ok {
				continue
			}
			rePort[key] = struct{}{}
			//save port
			result = append(result, &daemon.ListenPort{
				Port:   int(lport),
				Proto:  proto,
				HostIp: hostIp,
			})
		}
	}

	return result, nil
}

func GetContainerProcessInfo(pid int, basePath string) ([]*daemon.ProcessData, error) {
	if pid <= 0 {
		return nil, errors.Errorf("pid is error")
	}
	//get all process
	pids, err := GetProcessPid(pid, basePath)
	if err != nil {
		return nil, errors.Errorf("get all pid failed, %+v", err)
	}
	//get process start time function
	getProcStartTime := GetProcessStartTime()
	if getProcStartTime == nil {
		return nil, errors.Errorf("get process start time func is nil")
	}
	//process information
	data := make([]*daemon.ProcessData, 0, len(pids))
	//list
	for _, value := range pids {
		stime, err := getProcStartTime(value, basePath)
		if err != nil {
			logging.Get().Error().Msgf("get %v's start time failed, %+v.", err)
			continue
		}
		name, err := GetProcessName(value, basePath)
		if err != nil {
			logging.Get().Error().Msgf("get %v's process name failed, %v.", value, err)
			continue
		}
		username, err := GetProcessUser(value, basePath)
		if err != nil {
			logging.Get().Error().Msgf("get process user failed, %+v.", err)
			continue
		}
		//
		ret := &daemon.ProcessData{
			HostPid:      value,
			ContainerPid: 0,
			Comm:         name,
			UserName:     username,
			StartTime:    stime,
		}
		//print debug log
		logging.Get().Debug().Msgf("%+v.", *ret)
		//result
		data = append(data, ret)
	}
	//check
	if len(data) == 0 {
		return nil, errors.Errorf("get (pid:%+v) process data failed", pid)
	}
	//return
	return data, nil
}

func GetContainerProcess(pid int, basePath string) (string, bool) {
	if pid <= 0 {
		return "", false
	}
	//get process name
	name, err := GetProcessName(pid, basePath)
	if err != nil {
		return "", false
	}
	//get process pid
	pids, err := GetProcessPid(pid, basePath)
	if err != nil {
		return "", false
	}

	if len(pids) != 1 {
		for i := 0; i < len(pids); i++ {
			comm, err := GetProcessName(pids[i], basePath)
			if err != nil {
				return "", false
			}

			if comm == "pause" {
				continue
			}

			if comm != name {
				return "", false
			}
		}
	}

	return name, true
}
