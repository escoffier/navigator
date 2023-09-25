package handler

import (
	"errors"
	"fmt"
	rpcstream "gitlab.com/piccolo_su/vegeta/pkg/streaming"
	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
	"gitlab.com/security-rd/go-pkg/logging"
	"google.golang.org/protobuf/reflect/protoreflect"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

type NodeLoadHandler struct{}

func (nl *NodeLoadHandler) OnCreate(s rpcstream.Stream, reqID string, message protoreflect.ProtoMessage) {
	logging.Get().Info().Msgf("NodeLoadHandler 收到 grpc ，开始计算节点信息")
	req := message.(*pb.NodeLoadReq)
	logging.Get().Debug().Msg(req.String())
	resp := &pb.NodeLoadResp{}
	var err error
	// cpu
	resp.Cpu, err = nl.getCpuLoad()
	if err != nil {
		resp.ErrMsg = "cpu:" + err.Error()
	}
	// memory
	resp.MemoryUsed, err = nl.getMemoryUsed()
	if err != nil {
		resp.ErrMsg += "memory:" + err.Error()
	}
	// disk
	resp.DiskUsed, err = nl.getDiskUsed()
	if err != nil {
		resp.ErrMsg += "disk:" + err.Error()
	}
	logging.Get().Info().Msgf("NodeLoadHandler 完成 grpc ,%s", resp.String())
	s.SendResponse(reqID, resp)
}

func (nl *NodeLoadHandler) OnRead(s rpcstream.Stream, reqID string, msg protoreflect.ProtoMessage) {}

func (nl *NodeLoadHandler) OnUpdate(s rpcstream.Stream, reqID string, msg protoreflect.ProtoMessage) {
}

func (nl *NodeLoadHandler) OnDelete(s rpcstream.Stream, reqID string, msg protoreflect.ProtoMessage) {
}

func (nl *NodeLoadHandler) getCpuLoad() (string, error) {
	var idle2, total2 uint64
	contents, err := os.ReadFile("/host/proc/stat")
	if err != nil {
		logging.Get().Err(err).Msgf("Error reading /host/proc/stat")
		return "", err
	}
	// Find the line that starts with "cpu "
	lines := strings.Split(string(contents), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "cpu ") {
			fields := strings.Fields(line)
			if len(fields) < 5 {
				logging.Get().Err(err).Msgf("Error parsing /host/proc/stat")
				return "", err
			}
			// Parse the fields we need
			idle2, _ = strconv.ParseUint(fields[4], 10, 64)
			total2 = 0
			for i := 1; i < 5; i++ {
				val, _ := strconv.ParseUint(fields[i], 10, 64)
				total2 += val
			}
			break
		}
	}
	// Calculate the CPU usage percentage
	idleTicks := float64(idle2)
	totalTicks := float64(total2)
	cpuUsage := 100 * (totalTicks - idleTicks) / totalTicks
	// Print the result
	return fmt.Sprintf("%.2f%%", cpuUsage), nil
}

/*
ubuntu/Red Hat Enterprise Linux 7.1 or later (procps-ng 3.3.10).       Mem: used = MemTotal - MemFree - Buffers - Cached - Slab
Red Hat Enterprise Linux 5, 6, 7, 8 & 9.                                Mem: used = MemTotal - MemFree
*/
func (nl *NodeLoadHandler) getMemoryUsed() (string, error) {
	var is7xOrUbuntu bool
	contents, err := os.ReadFile("/etc/redhat-release") // 系统
	if err != nil {
		is7xOrUbuntu = true
	} else if strings.Contains(string(contents), "CentOS Linux release 7.") {
		is7xOrUbuntu = true
	}
	logging.Get().Err(err).Msgf("getMemoryUsed: is7xOrUbuntu:%v", is7xOrUbuntu)
	contents, err = os.ReadFile("/host/proc/meminfo")
	if err != nil {
		logging.Get().Err(err).Msgf("Error reading /host/proc/meminfo")
		return "", err
	}

	var (
		memTotal int64
		memFree  int64
		buffers  int64
		cached   int64
		slab     int64
	)
	lines := strings.Split(string(contents), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) != 3 {
				logging.Get().Err(err).Msgf("Error parsing /host/proc/meminfo. ", line)
				return "", err
			}
			size, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				logging.Get().Err(err).Msgf("Error parsing /host/proc/meminfo. ", line)
				return "0", err
			}
			memTotal = size
			continue
		}
		if strings.HasPrefix(line, "MemFree:") {
			fields := strings.Fields(line)
			if len(fields) != 3 {
				logging.Get().Err(err).Msgf("Error parsing /host/proc/meminfo. ", line)
				return "", err
			}
			size, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				logging.Get().Err(err).Msgf("Error parsing /host/proc/meminfo. ", line)
				return "0", err
			}
			memFree = size
			continue
		}
		if strings.HasPrefix(line, "Buffers:") {
			fields := strings.Fields(line)
			if len(fields) != 3 {
				logging.Get().Err(err).Msgf("Error parsing /host/proc/meminfo. ", line)
				return "", err
			}
			size, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				logging.Get().Err(err).Msgf("Error parsing /host/proc/meminfo. ", line)
				return "0", err
			}
			buffers = size
			continue
		}
		if strings.HasPrefix(line, "Cached:") {
			fields := strings.Fields(line)
			if len(fields) != 3 {
				logging.Get().Err(err).Msgf("Error parsing /host/proc/meminfo. ", line)
				return "", err
			}
			size, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				logging.Get().Err(err).Msgf("Error parsing /host/proc/meminfo. ", line)
				return "0", err
			}
			cached = size
			continue
		}
		if strings.HasPrefix(line, "Cached:") {
			fields := strings.Fields(line)
			if len(fields) != 3 {
				logging.Get().Err(err).Msgf("Error parsing /host/proc/meminfo. ", line)
				return "", err
			}
			size, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				logging.Get().Err(err).Msgf("Error parsing /host/proc/meminfo. ", line)
				return "0", err
			}
			slab = size
			continue
		}
	}
	if is7xOrUbuntu {
		return strconv.Itoa(int(memTotal - memFree - buffers - cached - slab)), nil
	}
	return strconv.Itoa(int(memTotal - memFree)), nil
}

func (nl *NodeLoadHandler) getDiskUsed() (string, error) {
	out, err := exec.Command("df", "-h", "/host/bin").Output()
	if err != nil {
		logging.Get().Err(err).Msgf("Error run: df -h")
		return "", errors.New("Error running df command:" + err.Error())
	}

	// Parse the output of the df command
	lines := strings.Split(string(out), "\n")
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) != 6 {
			continue
		}
		if fields[5] == "/host/bin" {
			return fields[2], nil
		}
	}
	return "", errors.New("not found target mountedPath:/")
}
