package netflow

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"runtime/debug"
	"sync"
	"time"

	ct "github.com/florianl/go-conntrack"
	"github.com/go-redis/redis/v8"
	json "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo"
	"gitlab.com/piccolo_su/vegeta/pkg/daemon"
	"gitlab.com/security-rd/go-pkg/cache"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/model"
)

const (
	unixSockFile = "/tmp/setns.sock"
	ebpfKeyStr   = "%v-%v:%v"
)

type ClusterManager interface {
	ClusterKey() (string, bool)
}

type FlowSession struct {
	url            string
	hostIP         string
	NetLog         bool
	NetFlowEnable  bool
	EbpfStat       int
	CtFlow         ConntrackTools
	sockClient     *net.UnixConn
	nodePodsInfo   *NodePodsInfo
	CriManage      nodeinfo.ContainerInfoManager
	clusterManager ClusterManager
	submitter      *Submitter
	nsDataChan     chan *daemon.NetSessionLink
	redisClient    *redis.Client
	netLinkData    map[uint32]*daemon.NetSessionLink
	EbpfNetInfo    map[string]*daemon.NetProcData
	ebpfLock       sync.Mutex
	netLock        sync.Mutex
}

func IpStringToUint32(value string) uint32 {
	ip := net.ParseIP(value)
	return binary.LittleEndian.Uint32(ip.To4())
}

func SessionToFiveTuple(data ct.Con, proto uint8) (*model.FiveTuple, *model.FiveTuple) {
	origin := data.Origin
	reply := data.Reply

	src := &model.FiveTuple{
		SrcIp:   origin.Src.String(),
		SrcPort: *origin.Proto.SrcPort,
		DstIp:   origin.Dst.String(),
		DstPort: *origin.Proto.DstPort,
		Proto:   proto,
	}

	dst := &model.FiveTuple{
		SrcIp:   reply.Src.String(),
		SrcPort: *reply.Proto.SrcPort,
		DstIp:   reply.Dst.String(),
		DstPort: *reply.Proto.DstPort,
		Proto:   proto,
	}

	return src, dst
}

func NetlinkToFiveTuple(data *ConntrackFlow, proto uint8) (*model.FiveTuple, *model.FiveTuple) {
	origin := &data.Forward
	reply := &data.Reverse

	src := &model.FiveTuple{
		SrcIp:   origin.SrcIP.String(),
		SrcPort: origin.SrcPort,
		DstIp:   origin.DstIP.String(),
		DstPort: origin.DstPort,
		Proto:   proto,
	}

	dst := &model.FiveTuple{
		SrcIp:   reply.SrcIP.String(),
		SrcPort: reply.SrcPort,
		DstIp:   reply.DstIP.String(),
		DstPort: reply.DstPort,
		Proto:   proto,
	}

	return src, dst
}

func (fs *FlowSession) SaveNetLinkData(netSession *daemon.NetSessionLink) {
	if netSession == nil {
		logging.Get().Error().Msgf("the argument is nil.")
		return
	}
	fs.netLock.Lock()
	defer fs.netLock.Unlock()

	netSession.CreatedAt = time.Now().Unix()
	key := netSession.CreateUuid()
	fs.netLinkData[key] = netSession
}

func (fs *FlowSession) DeleteNetLinkData(netSession *daemon.NetSessionLink) {
	if netSession == nil {
		logging.Get().Error().Msgf("the argument is nil.")
		return
	}

	fs.netLock.Lock()
	defer fs.netLock.Unlock()

	key := netSession.CreateUuid()
	delete(fs.netLinkData, key)
}

func (fs *FlowSession) GetEbpfNetData(proto uint8, ip string, port uint16) *daemon.NetProcData {
	addr := IpStringToUint32(ip)
	key := fmt.Sprintf(ebpfKeyStr, proto, addr, port)
	//lock
	fs.ebpfLock.Lock()
	defer fs.ebpfLock.Unlock()
	//find
	ret, ok := fs.EbpfNetInfo[key]
	if !ok {
		//print debug log
		//logging.Get().Info().Msgf("[find] find failed, key : %+v.", key)
		return nil
	}
	//delete
	delete(fs.EbpfNetInfo, key)

	return ret
}

func AllowProto(proto uint8) bool {
	switch proto {
	case IPPROTO_TCP:
		fallthrough
	case IPPROTO_UDP:
		return true
	}
	return false
}

func AllowTCPState(flow *ConntrackFlow, state uint8) bool {
	//tcp protocol
	if flow.Forward.Protocol != IPPROTO_TCP {
		return true
	}
	//tcp established state
	if flow.TcpState == state {
		return true
	}
	return false
}

func NetProtoConvert(proto uint8) uint8 {
	switch proto {
	case IPPROTO_TCP:
		return 1
	case IPPROTO_UDP:
		return 2
	default:

	}
	return 0
}

func NewFlowSession(k8sInfo *NodePodsInfo, crim nodeinfo.ContainerInfoManager, clusterManager ClusterManager, consoleURL string) (*FlowSession, error) {

	redisClient, err := cache.NewRedis()
	if err != nil {
		return nil, errors.Errorf("redis init failed, %v", err)
	}

	ctFlow := ConntrackTools{Groups: NF_NETLINK_CONNTRACK_UPDATE}
	//ctFlow := ConntrackTools{Groups: NF_NETLINK_CONNTRACK_NEW | NF_NETLINK_CONNTRACK_UPDATE}
	err = ctFlow.CreateConntrackSocket()
	if err != nil {
		return nil, errors.Errorf("Failed to get conntrack handle")
	}
	//get ebpf env
	ebpfEnable := false
	if ok := os.Getenv("EBPF_ENABLE"); ok == "true" {
		ebpfEnable = true
	}

	NetLog := false
	if ok := os.Getenv("NETLOG_ENABLE"); ok == "true" {
		NetLog = true
	}

	NetFlowEnable := true
	if ok := os.Getenv("NETFLOW_ENABLE"); ok == "false" {
		NetFlowEnable = false
	}
	//get host ip
	myHostIP := os.Getenv("MY_HOST_IP")
	if myHostIP == "" {
		return nil, errors.Errorf("Host IP (found=%s) is missing, set MY_HOST_IP env using k8s Downward API", myHostIP)
	}
	//console url
	url := fmt.Sprintf("%s/internal/platform/networkTopo/topologies", consoleURL)

	fs := FlowSession{
		CtFlow:         ctFlow,
		hostIP:         myHostIP,
		NetLog:         NetLog,
		NetFlowEnable:  NetFlowEnable,
		EbpfStat:       daemon.EBPF_FAILE,
		nodePodsInfo:   k8sInfo,
		clusterManager: clusterManager,
		CriManage:      crim,
		url:            url,
		nsDataChan:     make(chan *daemon.NetSessionLink, 5000),
		EbpfNetInfo:    make(map[string]*daemon.NetProcData),
		redisClient:    redisClient,
		submitter:      NewSubmitter(5*time.Minute, GetSubmitFunc(url)),
	}
	//
	err = fs.DialUnixSocket(unixSockFile)
	if err != nil {
		logging.Get().Error().Msgf("dial unix socket failed, %v", err)
	}
	//ebpf init
	fs.InitEbpf(ebpfEnable)

	return &fs, nil
}

func (fs *FlowSession) DialUnixSocket(address string) error {
	//create unix socket
	addr, err := net.ResolveUnixAddr("unix", address)
	if err != nil {
		return errors.Errorf("create unix socket client failed, %v", err)
	}
	//unix socket dial
	sockClient, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		return errors.Errorf("unix socket client dial failed, %v", err)
	}
	//
	fs.sockClient = sockClient
	return nil
}

func (fs *FlowSession) Start(ctx context.Context) {
	if !fs.NetFlowEnable {
		logging.Get().Warn().Msgf("netflow disable!!!")
		return
	}

	//handle queue data
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
			}
		}()
		//print log
		logging.Get().Info().Msgf("process net session start...")
		//process session
		fs.ProcSessionQueData()
	}()
	//wait get container information
	time.Sleep(10 * time.Second)
	//crontab check session
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
			}
		}()
		//print log
		logging.Get().Info().Msgf("conntrack session init list.")
		//list ipv4 session
		err := fs.conntrackInitList(ct.IPv4)
		if err != nil {
			logging.Get().Error().Msgf("init ipv4 session failed, %v.", err)
		}
		//list ipv4 session
		err = fs.conntrackInitList(ct.IPv6)
		if err != nil {
			logging.Get().Error().Msgf("init ipv6 session failed, %v.", err)
		}
	}()
	//handling timeout session
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
			}
		}()
		fs.HandleTimeoutSession()
	}()
	//handling timeout ebpf net data
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
			}
		}()
		fs.HandleEbpfNetDataTimeout()
	}()
	//listen conntrack event
	err := fs.CtFlow.RunConntrackEvent(fs.onFlowCallback)
	if err != nil {
		logging.Get().Error().Msgf("process conntrack event failed, %v.", err)
	}
}

func (fs *FlowSession) Close() {
	if fs.sockClient != nil {
		_ = fs.sockClient.Close()
	}
	//close conntrack resource
	fs.CtFlow.Close()
}

func (fs *FlowSession) HandleTimeoutSession() {
	var timeout int64 = 30 //30 second
	for {
		nowTime := time.Now().Unix()
		time.Sleep(30 * time.Second)
		//
		fs.netLock.Lock()
		for key, value := range fs.netLinkData {
			if nowTime-value.CreatedAt < timeout {
				continue
			}
			//delete
			delete(fs.netLinkData, key)
			//handle timeout data
			value.NlType = NFCT_T_TIMEOUT
			err := fs.ProcSessionData(value)
			if err != nil {
				logging.Get().Error().Msgf("handle timeout session error! %+v", *value)
			}
		}
		fs.netLock.Unlock()
	}
}

func (fs *FlowSession) HandleEbpfNetDataTimeout() {
	if fs.EbpfStat != daemon.EBPF_SUCC {
		return
	}

	var timeout int64 = 30 //30 second
	for {
		nowTime := time.Now().Unix()
		time.Sleep(30 * time.Second)
		//delete
		fs.ebpfLock.Lock()
		for key, value := range fs.EbpfNetInfo {
			if nowTime-value.CreatedAt < timeout {
				continue
			}

			if value.SrcAddr == 0 || value.DstAddr == 0 {
				continue
			}

			delete(fs.EbpfNetInfo, key)
		}
		fs.ebpfLock.Unlock()
		//debug map length
		num := len(fs.EbpfNetInfo)
		if num > 2000 {
			logging.Get().Info().Msgf("[ebpf] map data len : %+v.")
		}
	}
}

func (fs *FlowSession) RetrySendData(data []byte) error {
	var err error

	for i := 0; i < 3; i++ {
		_, err = fs.sockClient.Write(data)
		if err != nil {
			logging.Get().Error().Msgf("send net info to setns process failed, %v", err)
			//sleep wait
			time.Sleep(1 * time.Second)
			//unix socket dial
			err = fs.DialUnixSocket(unixSockFile)
			if err != nil {
				logging.Get().Error().Msgf("dial unix socket failed, %v", err)
			}
			continue
		}
		break
	}

	if err != nil {
		return err
	}

	return nil
}

func (fs *FlowSession) InitEbpf(enable bool) {
	//get ebpf state
	fs.SetEbpfState(enable)
	//print debug log
	logging.Get().Info().Msgf("ebpf state : %v", fs.EbpfStat)
	//ebpf filter invalid address
	err := fs.SetEbpfFilterAddrs("127.0.0.1", fs.hostIP)
	if err != nil {
		logging.Get().Error().Msgf("set ebpf filter address failed, %v.", err)
	}
}

func (fs *FlowSession) SetEbpfFilterAddrs(addrs ...string) error {
	//set ebpf state success
	if fs.EbpfStat != daemon.EBPF_SUCC {
		return nil
	}

	netAddrs := make([]uint32, 0)
	for _, value := range addrs {
		addr := IpStringToUint32(value)
		netAddrs = append(netAddrs, addr)
	}

	config := daemon.EbpfFilterAddr{
		DataType: daemon.DATA_FILTER,
		Addrs:    netAddrs,
	}

	data, err := json.Marshal(config)
	if err != nil {
		logging.Get().Error().Msgf("json marshal ebpf filter addrs failed, %v.", err)
		return err
	}

	err = fs.RetrySendData(data)
	if err != nil {
		logging.Get().Error().Msgf("send ebpf filter addrs failed, %v.", err)
		return err
	}
	return nil
}

func (fs *FlowSession) GetNetDataFromEbpf() bool {
	if fs.sockClient == nil {
		return false
	}
	//get ebpf state
	data := fmt.Sprintf("{\"data_type\":%v}", daemon.DATA_EBPF)
	//send
	err := fs.RetrySendData([]byte(data))
	if err != nil {
		logging.Get().Error().Msgf("send get ebpf net data request failed, %+v.", err)
		return false
	}

	var length int
	rcvBuf := make([]byte, 102400)
	readsign := make(chan struct{}, 1)
	go func() {
		length, err = fs.sockClient.Read(rcvBuf)
		if err != nil {
			logging.Get().Error().Msgf("read unix socket response data failed, %v", err)
			return
		}
		readsign <- struct{}{}
		close(readsign)
	}()
	//ebpf net data
	var netData []daemon.EbpfNetData
	//parse json
	select {
	case <-time.After(time.Second * 3):
		logging.Get().Warn().Msgf("get ebpf net data timeout!")

	case <-readsign:
		//print debug log
		//logging.Get().Info().Msgf("receive data len : %+v.", length)
		err = json.Unmarshal(rcvBuf[:length], &netData)
		if err != nil || len(netData) == 0 {
			return false
		}
		//print debug log
		//logging.Get().Info().Msgf("receive data num : %+v.", len(netData))
		//lock
		fs.ebpfLock.Lock()
		for i := 0; i < len(netData); i++ {
			key := fmt.Sprintf(ebpfKeyStr, netData[i].Proto, netData[i].Saddr, netData[i].Sport)
			value := &daemon.NetProcData{
				CreatedAt: time.Now().Unix(),
				Pid:       netData[i].Pid,
				SrcAddr:   netData[i].Saddr,
				DstAddr:   netData[i].Daddr,
				ProcName:  netData[i].ProcName,
			}
			//save data
			fs.EbpfNetInfo[key] = value
			//print debug log
			//logging.Get().Info().Msgf("[save] key : %+v, value : %+v", key, *value)
		}
		fs.ebpfLock.Unlock()
	}

	return true
}

func (fs *FlowSession) GetNetProcInfo(netRes *model.TensorNetworkFlow, src, dst *daemon.K8sResData, addr *model.FiveTuple) (bool, error) {
	if netRes == nil || addr == nil {
		return false, fmt.Errorf("argument point is nil")
	}

	if src != nil {
		data := fs.GetEbpfNetData(addr.Proto, addr.SrcIp, addr.SrcPort)
		if data == nil {
			//get net data
			ok := fs.GetNetDataFromEbpf()
			if !ok {
				return false, nil //fmt.Errorf("get src net data is nil from ebpf.")
			}

			data = fs.GetEbpfNetData(addr.Proto, addr.SrcIp, addr.SrcPort)
			if data == nil {
				return false, fmt.Errorf("find src ebpf net data failed")
			}
		}
		//
		containerId := ""
		containerName := ""
		for id, containerData := range src.ContainerInfo {
			if containerData.ContainerPid == data.Pid {
				containerId = id
				containerName = containerData.ContainerName
				break
			}
		}
		//check container id
		if containerId == "" {
			return false, errors.Errorf("source container id is nil")
		}
		//
		netRes.SrcProcess = data.ProcName
		netRes.SrcContainerID = containerId
		netRes.SrcContainerName = containerName
		netRes.SrcPid = data.Pid
		//return
		if dst == nil {
			return redisSaveOrUpdate(fs.redisClient, daemon.SND_ADDR, netRes)
		}
	}

	if dst != nil {
		data := fs.GetEbpfNetData(addr.Proto, addr.DstIp, addr.DstPort)
		if data == nil {
			//get net data
			ok := fs.GetNetDataFromEbpf()
			if !ok {
				return false, fmt.Errorf("get src net data is nil from ebpf")
			}
			//find
			data = fs.GetEbpfNetData(addr.Proto, addr.DstIp, addr.DstPort)
			if data == nil {
				return false, fmt.Errorf("find dst ebpf net data failed")
			}
		}
		//
		containerId := ""
		containerName := ""
		for id, containerData := range dst.ContainerInfo {
			if containerData.ContainerPid == data.Pid {
				containerId = id
				containerName = containerData.ContainerName
				break
			}
		}
		//check container id
		if containerId == "" {
			return false, errors.Errorf("dst container id is nil")
		}
		//
		netRes.DstProcess = data.ProcName
		netRes.DstContainerID = containerId
		netRes.DstContainerName = containerName
		netRes.DstPid = data.Pid
		//return
		return redisSaveOrUpdate(fs.redisClient, daemon.RCV_ADDR, netRes)
	}

	return false, fmt.Errorf("src and dst info is nil")
}

func (fs *FlowSession) SetEbpfState(enable bool) {
	if fs.sockClient == nil {
		return
	}
	//get ebpf state
	data := fmt.Sprintf("{\"data_type\":%v,\"enable\":%v}", daemon.DATA_EBPF_STATE, enable)
	//send
	err := fs.RetrySendData([]byte(data))
	if err != nil {
		return
	}

	var length int
	rcvBuf := make([]byte, 128)
	readsign := make(chan struct{}, 1)
	go func() {
		length, err = fs.sockClient.Read(rcvBuf)
		if err != nil {
			logging.Get().Error().Msgf("read unix socket response data failed, %v", err)
			return
		}
		readsign <- struct{}{}
		close(readsign)
	}()

	type EbpfState struct {
		State int `json:"ebpf_state"`
	}

	select {
	case <-time.After(time.Second * 2):
		length = 0

	case <-readsign:
		//logging.Get().Info().Msgf("receive data : %v", string(rcvBuf[:length]))
		var state EbpfState
		err = json.Unmarshal(rcvBuf[:length], &state)
		if err != nil {
			return
		}
		//
		fs.EbpfStat = state.State
	}
}

func (fs *FlowSession) GetProcessName(netinfo *daemon.PidAssociateMnt) (*daemon.ProcessInfo, error) {
	if fs.sockClient == nil {
		return nil, errors.Errorf("udp client is nil")
	}

	data, err := json.Marshal(netinfo)
	if err != nil {
		return nil, errors.Errorf("json marshal failed, %v", err)
	}

	err = fs.RetrySendData(data)
	if err != nil {
		return nil, errors.Errorf("retry send data failed, %v", err)
	}

	length := 0
	rcvBuf := make([]byte, 512)
	readsign := make(chan struct{}, 1)
	//read data
	go func() {
		length, err = fs.sockClient.Read(rcvBuf)
		if err != nil {
			logging.Get().Error().Msgf("read unix socket response data failed, %v", err)
			return
		}
		readsign <- struct{}{}
		close(readsign)
	}()

	select {
	case <-time.After(time.Second * 2):
		length = 0

	case <-readsign:
		//check data length
		if length <= 0 {
			return nil, errors.Errorf("read unix response's data length is %v", length)
		}
		//logging.Get().Info().Msgf("receive data : %v", string(rcvBuf[:length]))
		var pInfo daemon.ProcessInfo
		err = json.Unmarshal(rcvBuf[:length], &pInfo)
		if err != nil {
			return nil, errors.Errorf("json unmarshal with setns process response data failed, %v", err)
		}
		//return
		return &pInfo, nil
	}

	return nil, errors.Errorf("read unix response timeout")
}

func (fs *FlowSession) GetContainerProcessName(addrType uint8, res *daemon.K8sResData, tuple *model.FiveTuple) (*daemon.ProcessInfo, error) {
	if len(res.ContainerInfo) == 1 {
		for id, container := range res.ContainerInfo {
			pid := container.ContainerPid
			comm, ok := nodeinfo.GetContainerProcess(pid, "/host")
			if !ok {
				break
			}
			return &daemon.ProcessInfo{
				Pid:           pid,
				Status:        daemon.GET_DATA_SUCC,
				ProcName:      comm,
				ContainerName: container.ContainerName,
				ContainerId:   id,
			}, nil
		}
	}

	//default value
	var defValue daemon.ProcessInfo
	defValue.Pid = 0
	//list containers
	for id, containerData := range res.ContainerInfo {
		if len(id) == 0 || len(containerData.ContainerName) == 0 {
			logging.Get().Warn().Msgf("[container-warn] container id : %v, container name : %v, podname : %+v.", id, containerData.ContainerName, res.PodName)
			continue
		}
		//logging.Get().Info().Msgf("get pid : %v, ns : %v, pod name : %v, %+v", pid, namespace, podname, *tuple)
		netInfo := &daemon.PidAssociateMnt{
			DataType:  daemon.DATA_SETNS,
			Pid:       containerData.ContainerPid,
			AddrType:  addrType,
			TupleInfo: *tuple,
		}
		//get process
		pInfo, err := fs.GetProcessName(netInfo)
		if err != nil {
			logging.Get().Warn().Msgf("get process failed, ns : %v, pod : %v, tuple : %+v, container : %v, error : %v", res.Namespace, res.PodName, *tuple, containerData.ContainerName, err)
			continue
		}
		//container name
		pInfo.ContainerId = id
		pInfo.ContainerName = containerData.ContainerName
		//success
		if pInfo.Status == daemon.GET_DATA_SUCC {
			return pInfo, nil
		}
		//status
		if len(res.ContainerInfo) == 1 {
			if pInfo.Pid == 0 || len(pInfo.ProcName) == 0 {
				return nil, errors.Errorf("process info error, ns : %v, pod : %v, netinfo : %+v, container : %+v", res.Namespace, res.PodName, *netInfo, *pInfo)
			}
			return pInfo, nil
		} else {
			if defValue.Pid == 0 && pInfo.Pid != 0 {
				defValue.Pid = pInfo.Pid
				defValue.Status = pInfo.Status
				defValue.Timeout = pInfo.Timeout
				defValue.ProcName = pInfo.ProcName
				defValue.ContainerId = pInfo.ContainerId
				defValue.ContainerName = pInfo.ContainerName
			}

			if pInfo.Pid == 0 {
				logging.Get().Warn().Msgf("ns : %v, pod : %v, container : %+v, cpid : %v.", res.Namespace, res.PodName, *pInfo, containerData.ContainerPid)
			}
		}
	}

	if defValue.Pid != 0 {
		return &defValue, nil
	}

	return nil, errors.Errorf("container error, ns : %v, pod name : %v, num : %v, tuple : %+v", res.Namespace, res.PodName, len(res.ContainerInfo), *tuple)
}

func (fs *FlowSession) GetContainerInfo(netRes *model.TensorNetworkFlow, src, dst *daemon.K8sResData, addr *model.FiveTuple) (bool, error) {

	if src != nil {
		pinfo, err := fs.GetContainerProcessName(daemon.SND_ADDR, src, addr)
		if err != nil {
			errn := fs.nodePodsInfo.UpdateContainerData(fs.CriManage, addr.SrcIp, src.Namespace, src.PodName)
			if errn != nil {
				logging.Get().Err(errn).Msg("update src container failed")
			}
			return false, errors.Errorf("get src container process name failed, %v", err)
		}
		netRes.SrcProcess = pinfo.ProcName
		netRes.SrcContainerID = pinfo.ContainerId
		netRes.SrcContainerName = pinfo.ContainerName
		netRes.SrcPid = pinfo.Pid
		//return
		if dst == nil {
			return redisSaveOrUpdate(fs.redisClient, daemon.SND_ADDR, netRes)
		}
	}

	if dst != nil {
		key := fmt.Sprintf("%v-%v", addr.Proto, addr.DstPort)
		process, ok := dst.ListenPorts[key]
		if !ok {
			pinfo, err := fs.GetContainerProcessName(daemon.RCV_ADDR, dst, addr)
			if err != nil {
				errn := fs.nodePodsInfo.UpdateContainerData(fs.CriManage, addr.DstIp, dst.Namespace, dst.PodName)
				if errn != nil {
					logging.Get().Err(errn).Msg("update dst container failed")
				}
				return false, errors.Errorf("get dst container process name failed, %v", err)
			}
			//process timeout
			pinfo.Timeout = time.Now().Unix()
			//save process information
			dst.ListenPorts[key] = pinfo
			netRes.DstProcess = pinfo.ProcName
			netRes.DstContainerID = pinfo.ContainerId
			netRes.DstContainerName = pinfo.ContainerName
			netRes.DstPid = pinfo.Pid
		} else {
			netRes.DstProcess = process.ProcName
			netRes.DstContainerID = process.ContainerId
			netRes.DstContainerName = process.ContainerName
			netRes.DstPid = process.Pid
			//timeout
			if time.Now().Unix()-process.Timeout > 600 {
				delete(dst.ListenPorts, key)
			}
		}
		//return
		return redisSaveOrUpdate(fs.redisClient, daemon.RCV_ADDR, netRes)
	}

	return false, nil
}

func (fs *FlowSession) ProcSessionQueData() {
	for {
		select {
		case data, ok := <-fs.nsDataChan:
			if !ok {
				logging.Get().Warn().Msgf("netflow data chan closed!")
				fs.nsDataChan = nil
				return
			}
			//proc session
			err := fs.ProcSessionData(data)
			if err != nil {
				logging.Get().Warn().Err(err).Msg("get container info failed")
			}
		}
	}
}

func (fs *FlowSession) PutNetSession(nlType, netType uint8, origin, reply *model.FiveTuple) {
	ok := fs.filterUnusedSession(origin)
	if !ok {
		return
	}

	nsData := &daemon.NetSessionLink{
		NlType:   nlType,
		DataType: netType,
		Origin:   *origin,
		Reply:    *reply,
	}

	timer := time.NewTimer(200 * time.Millisecond)
	defer timer.Stop()

	select {
	case fs.nsDataChan <- nsData:
	case <-timer.C:
		logging.Get().Warn().Msgf("send to queue timeout: %+v", nsData)
	}
}

func (fs *FlowSession) AllowLinkState(proto uint8, session ct.Con) bool {
	//link state
	if session.Status != nil && !(*session.Status&IPS_SEEN_REPLY == IPS_SEEN_REPLY) {
		return false
	}
	//tcp link state
	if proto == IPPROTO_TCP {
		if session.ProtoInfo == nil || session.ProtoInfo.TCP == nil || session.ProtoInfo.TCP.State == nil {
			return false
		}

		if *session.ProtoInfo.TCP.State != TCP_CONNTRACK_ESTABLISHED {
			return false
		}
	}

	return true
}

func (fs *FlowSession) filterUnusedSession(addr *model.FiveTuple) bool {
	if addr.SrcIp == "127.0.0.1" || addr.DstIp == "127.0.0.1" {
		return false
	}

	if addr.SrcIp == fs.hostIP || addr.DstIp == fs.hostIP {
		return false
	}

	//filter dns
	if (addr.Proto == IPPROTO_UDP) && (addr.SrcPort == 53 || addr.DstPort == 53) {
		return false
	}

	return true
}

func (fs *FlowSession) ProcSessionData(netSession *daemon.NetSessionLink) error {
	defer func() {
		if r := recover(); r != nil {
			logging.Get().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
		}
	}()
	/*
		switch netSession.NlType {
		case NFCT_T_NEW:
			fs.SaveNetLinkData(netSession)
			return nil
		case NFCT_T_UPDATE, NFCT_T_TIMEOUT:
			fs.DeleteNetLinkData(netSession)
		default:
			return nil
		}
	*/
	//match pod information
	src, srcOk := fs.nodePodsInfo.GetResDataByIp(netSession.Origin.SrcIp)
	dst, dstOk := fs.nodePodsInfo.GetResDataByIp(netSession.Reply.SrcIp)
	//源地址和目的地址都没有查询到pod信息时,则丢弃该session
	if !srcOk && !dstOk {
		logging.Get().Warn().Msgf("query k8s resource failed. %+v", *netSession)
		return nil
	}
	//get cluster key
	clusterKey, ok := fs.clusterManager.ClusterKey()
	if !ok {
		clusterKey = "default"
	}
	//network flow
	netData := new(model.TensorNetworkFlow)
	//get src resource
	if src != nil {
		//source resource
		netData.SrcOwnerName = src.OwnerName
		netData.SrcKind = src.Kind
		netData.SrcNamespace = src.Namespace
		netData.SrcPodName = src.PodName
		netData.SrcCluster = clusterKey
	}
	//get dst resource
	if dst != nil {
		netData.DstOwnerName = dst.OwnerName
		netData.DstKind = dst.Kind
		netData.DstNamespace = dst.Namespace
		netData.DstPodName = dst.PodName
		netData.DstCluster = clusterKey
	}
	//dst ip address
	netData.DstPort = netSession.Reply.SrcPort
	//network flow time
	netData.CreatedAt = time.Now()
	netData.UpdatedAt = time.Now()
	netData.Status = int(netSession.NlType)
	netData.Proto = NetProtoConvert(netSession.Origin.Proto)
	//five tuple
	netAddr := &model.FiveTuple{
		Proto:   netSession.Origin.Proto,
		SrcPort: netSession.Origin.SrcPort,
		SrcIp:   netSession.Origin.SrcIp,
		DstPort: netData.DstPort,
		DstIp:   netSession.Reply.SrcIp,
	}
	//create associate key
	netData.CreateAssocKey(netAddr)
	//put net flow information
	var state bool
	var err error
	//
	switch netSession.NlType {
	case NFCT_T_UPDATE: //update event
		if (fs.EbpfStat == daemon.EBPF_SUCC) && (netSession.DataType == daemon.NET_UPDATE) {
			state, err = fs.GetNetProcInfo(netData, src, dst, netAddr)
			//debug log
			//if err != nil {
			//	logging.Get().Info().Msgf("[ebpf] get proc failed, %+v, %+v.", err, *netAddr)
			//}
		} else {
			//get container info
			state, err = fs.GetContainerInfo(netData, src, dst, netAddr)
			if err != nil {
				logging.Get().Err(err).Msg("get container info failed")
			}
		}

	case NFCT_T_TIMEOUT: //session timeout
		addrType := daemon.RCV_ADDR
		if src != nil {
			addrType = daemon.SND_ADDR
		}
		state, err = redisSaveOrUpdate(fs.redisClient, addrType, netData)
		if err != nil {
			logging.Get().Error().Msgf("get resource info failed, %v.", err)
		}

	default:
		return nil
	}

	//state
	if !state {
		return nil
	}
	//create uuid
	netData.CreateUuid()
	//print debug log
	if fs.NetLog {
		logging.Get().Info().Msgf("[post] %+v, %+v", *netSession, *netData)
	}
	//post net flow
	return fs.submitter.Submit(context.Background(), netData)
}

func (fs *FlowSession) conntrackInitList(family ct.Family) error {
	nfct, err := ct.Open(&ct.Config{})
	if err != nil {
		return errors.Errorf("conntrack open faied, %v", err)
	}

	defer func() {
		_ = nfct.Close()
	}()

	// Get all IPv4 entries of the expected table.
	sessions, err := nfct.Dump(ct.Conntrack, family)
	if err != nil {
		return errors.Errorf("conntrack dump failed, %v", err)
	}

	// Print out all expected sessions.
	for _, session := range sessions {
		if session.Origin == nil || session.Origin.Proto == nil || session.Origin.Proto.Number == nil {
			continue
		}

		proto := *session.Origin.Proto.Number
		if !AllowProto(proto) {
			continue
		}

		if !fs.AllowLinkState(proto, session) {
			continue
		}

		origin, reply := SessionToFiveTuple(session, proto)
		//put net session
		fs.PutNetSession(NFCT_T_UPDATE, daemon.NET_INIT, origin, reply)
	}

	return nil
}

func (fs *FlowSession) onFlowCallback(header *NlMsgHdr, flow *ConntrackFlow) error {
	var nfType uint8
	nlType := header.Type & 0xff
	iptuple := &flow.Forward

	/*protocol*/
	if !AllowProto(iptuple.Protocol) {
		return nil
	}

	/*message type*/
	switch nlType {
	case IPCTNL_MSG_CT_NEW:
		if flow.Forward.SrcPort == 53 || flow.Forward.DstPort == 53 {
			return nil
		}
		//get link state
		if (header.Flags & NLM_F_CREATE) == NLM_F_CREATE {
			nfType = NFCT_T_NEW
		} else {
			nfType = NFCT_T_UPDATE
			//tcp state != established
			if !AllowTCPState(flow, TCP_CONNTRACK_ESTABLISHED) {
				return nil
			}
		}

		origin, reply := NetlinkToFiveTuple(flow, iptuple.Protocol)
		//put net session
		fs.PutNetSession(nfType, daemon.NET_UPDATE, origin, reply)

	case IPCTNL_MSG_CT_DELETE:
		nfType = NFCT_T_DESTROY
		logging.Get().Warn().Msgf("this netlink msg type is error, %v, %v, %v.", header.Type, nlType, nfType)

	default:
		logging.Get().Warn().Msgf("this netlink msg type is error, %v, %v.", header.Type, nlType)
	}

	return nil
}
