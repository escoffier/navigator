package daemon

const (
	RCV_ADDR = 1
	SND_ADDR = 2
)

type K8sResData struct {
	Cluster   string `json:"cluster"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	PodName   string `json:"pod_name"`
	NodeIp    string `json:"node_ip"`
}

//session five tuple
type FiveTuple struct {
	SrcIp   string `json:"src_ip"`
	DstIp   string `json:"dst_ip"`
	SrcPort uint16 `json:"src_port"`
	DstPort uint16 `json:"dst_port"`
	Proto   uint8  `json:"proto"`
}

type NetSessionLink struct {
	NlType uint8
	Origin *FiveTuple
	Reply  *FiveTuple
}

//associate process
type NetAssocPod struct {
	SrcNamespace string
	SrcPodName   string
	SrcNodeIp    string
	DstNamespace string
	DstPodName   string
	DstNodeIp    string
	NetAddr      *FiveTuple
}

type PidAssociateMnt struct {
	Pid       int       `json:"pid"`
	AddrType  uint8     `json:"addr_type"`
	TupleInfo FiveTuple `json:"tuple_info"`
}

type ProcessInfo struct {
	Pid      int    `json:"pid"`
	ProcName string `json:"proc_name"`
}
