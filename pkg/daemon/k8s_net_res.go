package daemon

import (
	"bytes"
	"hash/fnv"
	"strconv"
)

const (
	RCV_ADDR      = 1
	SND_ADDR      = 2
	MATCH_SUCC    = 1
	GET_DATA_SUCC = 2
)

const (
	DATA_SETNS      = 0
	DATA_EBPF       = 1
	DATA_FILTER     = 2
	DATA_EBPF_STATE = 3
)

const (
	EBPF_FAILE = 0
	EBPF_SUCC  = 1
)

const (
	NET_INIT   = 0
	NET_UPDATE = 1
)

type K8sResData struct {
	Cluster       string                    `json:"cluster"`
	OwnerName     string                    `json:"owner_name"`
	Kind          string                    `json:"kind"`
	Namespace     string                    `json:"namespace"`
	PodName       string                    `json:"pod_name"`
	ContainerInfo map[string]*ContainerData `json:"container_id"` //container ID -> container data
	ListenPorts   map[string]*ProcessInfo   `json:"listen_ports"` //listen port -> process information
}

// session five tuple
type FiveTuple struct {
	SrcIp   string `json:"src_ip"`
	DstIp   string `json:"dst_ip"`
	SrcPort uint16 `json:"src_port"`
	DstPort uint16 `json:"dst_port"`
	Proto   uint8  `json:"proto"`
}

type EbpfNetData struct {
	Proto    int    `json:"proto"`
	Sport    int    `json:"sport"`
	Saddr    uint32 `json:"saddr"`
	Dport    int    `json:"dport"`
	Daddr    uint32 `json:"daddr"`
	Pid      int    `json:"pid"`
	Status   int    `json:"status"`
	ProcName string `json:"proc_name"`
}

type NetProcData struct {
	CreatedAt int64
	Pid       int
	SrcAddr   uint32
	DstAddr   uint32
	ProcName  string
}

type EbpfFilterAddr struct {
	DataType int      `json:"data_type"`
	Addrs    []uint32 `json:"addrs"`
}

type ContainerData struct {
	ContainerName string `json:"container_name"`
	ContainerPid  int    `json:"container_pid"`
}

type PidAssociateMnt struct {
	DataType  int       `json:"data_type"`
	Pid       int       `json:"pid"`
	AddrType  uint8     `json:"addr_type"`
	TupleInfo FiveTuple `json:"tuple_info"`
}

type ProcessInfo struct {
	Pid           int    `json:"pid"`
	Status        int    `json:"status"`
	ProcName      string `json:"proc_name"`
	ContainerName string `json:"-"`
	Timeout       int64  `json:"-"`
}

type NetSessionLink struct {
	NlType    uint8
	DataType  uint8
	CreatedAt int64
	Origin    FiveTuple
	Reply     FiveTuple
}

func (nets NetSessionLink) CreateUuid() uint32 {
	var buf bytes.Buffer
	//protocol
	buf.WriteByte(nets.Origin.Proto)
	//origin information
	buf.WriteString(nets.Origin.SrcIp)
	buf.WriteString(strconv.Itoa(int(nets.Origin.SrcPort)))
	buf.WriteString(nets.Origin.DstIp)
	buf.WriteString(strconv.Itoa(int(nets.Origin.DstPort)))
	//reply information
	buf.WriteString(nets.Reply.SrcIp)
	buf.WriteString(strconv.Itoa(int(nets.Reply.SrcPort)))
	buf.WriteString(nets.Reply.DstIp)
	buf.WriteString(strconv.Itoa(int(nets.Reply.DstPort)))
	//hash
	h := fnv.New32a()
	h.Write(buf.Bytes())
	return h.Sum32()
}
