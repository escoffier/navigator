package netflow

import (
	"context"
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
	"gitlab.com/piccolo_su/vegeta/pkg/daemon"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/logging"
)

const unixSockFile = "/tmp/setns.sock"

type ClusterManager interface {
	ClusterKey() (string, bool)
}

type FlowSession struct {
	CtFlow         ConntrackTools
	sockClient     *net.UnixConn
	hostIP         string
	k8sResInfos    *NodeResourceInfo
	url            string
	clusterManager ClusterManager
	submitter      *Submitter
	nsDataChan     chan daemon.NetSessionLink
	redisClient    *redis.Client
	netLinkData    map[uint32]*daemon.NetSessionLink
	lock           sync.Mutex
}

func SessionToFiveTuple(data ct.Con, proto uint8) (*daemon.FiveTuple, *daemon.FiveTuple) {
	origin := data.Origin
	reply := data.Reply

	src := &daemon.FiveTuple{
		SrcIp:   origin.Src.String(),
		SrcPort: *origin.Proto.SrcPort,
		DstIp:   origin.Dst.String(),
		DstPort: *origin.Proto.DstPort,
		Proto:   proto,
	}

	dst := &daemon.FiveTuple{
		SrcIp:   reply.Src.String(),
		SrcPort: *reply.Proto.SrcPort,
		DstIp:   reply.Dst.String(),
		DstPort: *reply.Proto.DstPort,
		Proto:   proto,
	}

	return src, dst
}

func NetlinkToFiveTuple(data *ConntrackFlow, proto uint8) (*daemon.FiveTuple, *daemon.FiveTuple) {
	origin := &data.Forward
	reply := &data.Reverse

	src := &daemon.FiveTuple{
		SrcIp:   origin.SrcIP.String(),
		SrcPort: origin.SrcPort,
		DstIp:   origin.DstIP.String(),
		DstPort: origin.DstPort,
		Proto:   proto,
	}

	dst := &daemon.FiveTuple{
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
	fs.lock.Lock()
	defer fs.lock.Unlock()

	netSession.CreatedAt = time.Now().Unix()
	key := netSession.CreateUuid()
	fs.netLinkData[key] = netSession
}

func (fs *FlowSession) DeleteNetLinkData(netSession *daemon.NetSessionLink) {
	if netSession == nil {
		logging.Get().Error().Msgf("the argument is nil.")
		return
	}

	fs.lock.Lock()
	defer fs.lock.Unlock()

	key := netSession.CreateUuid()
	delete(fs.netLinkData, key)
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

func NewFlowSession(k8sClient *K8sResClient, clusterManager ClusterManager, consoleURL string) (*FlowSession, error) {

	redisClient, err := RedisInit()
	if err != nil {
		return nil, errors.Errorf("redis init failed, %v", err)
	}

	ctFlow := ConntrackTools{Groups: NF_NETLINK_CONNTRACK_UPDATE}
	//ctFlow := ConntrackTools{Groups: NF_NETLINK_CONNTRACK_NEW | NF_NETLINK_CONNTRACK_UPDATE}
	err = ctFlow.CreateConntrackSocket()
	if err != nil {
		return nil, errors.Errorf("Failed to get conntrack handle")
	}

	myPodIP := os.Getenv("MY_POD_IP")
	if myPodIP == "" {
		return nil, errors.Errorf("Pod IP (found=%s) is missing, set MY_POD_IP env using k8s Downward API", myPodIP)
	}

	myHostIP := os.Getenv("MY_HOST_IP")
	if myPodIP == "" {
		return nil, errors.Errorf("Host IP (found=%s) is missing, set MY_HOST_IP env using k8s Downward API", myPodIP)
	}

	if myPodIP != myHostIP {
		return nil, errors.Errorf("Pod IP (found=%s) must equal Host IP (found=%s), check if hostNetwork is true", myPodIP, myHostIP)
	}

	url := fmt.Sprintf("%s/internal/platform/networkTopo/topologies", consoleURL)

	fs := FlowSession{
		CtFlow:         ctFlow,
		hostIP:         myHostIP,
		k8sResInfos:    k8sClient.nodeResInfo,
		clusterManager: clusterManager,
		url:            url,
		nsDataChan:     make(chan daemon.NetSessionLink, 300),
		redisClient:    redisClient,
		submitter:      NewSubmitter(1*time.Minute, GetSubmitFunc(url)),
	}
	//
	err = fs.DialUnixSocket(unixSockFile)
	if err != nil {
		logging.Get().Error().Msgf("dial unix socket failed, %v", err)
	}

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
	//handle queue data
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
			}
		}()
		//process session
		fs.ProcSessionQueData()
	}()

	//crontab check session
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
			}
		}()
		//print log
		logging.Get().Info().Msgf("conntrack session init list.")
		//list session
		err := fs.conntrackInitList(ctx)
		if err != nil {
			logging.Get().Error().Msgf("init session failed, %v.", err)
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
	//listen conntrack event
	err := fs.CtFlow.RunConntrackEvent(fs.onFlowCallback)
	if err != nil {
		logging.Get().Error().Msgf("process conntrack event failed, %v.", err)
	}
}

func (fs *FlowSession) Close() {
	if fs.sockClient != nil {
		fs.sockClient.Close()
	}
	//close conntrack resource
	fs.CtFlow.Close()
}

func (fs *FlowSession) HandleTimeoutSession() {
	var timeout int64 = 30 //30 second
	for {
		nowTime := time.Now().Unix()
		time.Sleep(30 * time.Second)
		for key, value := range fs.netLinkData {
			if nowTime-value.CreatedAt < timeout {
				continue
			}
			fs.lock.Lock()
			delete(fs.netLinkData, key)
			fs.lock.Unlock()
			//handle timeout data
			value.NlType = NFCT_T_TIMEOUT
			err := fs.ProcSessionData(value)
			if err != nil {
				logging.Get().Error().Msgf("handle timeout session error! %+v", *value)
			}
		}
	}
}

func (fs *FlowSession) RetrySendData(netinfo *daemon.PidAssociateMnt) error {
	data, err := json.Marshal(netinfo)
	if err != nil {
		return errors.Errorf("json marshal failed, %v", err)
	}

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

func (fs *FlowSession) GetProcessName(netinfo *daemon.PidAssociateMnt) (*daemon.ProcessInfo, error) {
	if fs.sockClient == nil {
		return nil, errors.Errorf("udp client is nil")
	}

	err := fs.RetrySendData(netinfo)
	if err != nil {
		return nil, errors.Errorf("retry send data failed, %v", err)
	}

	var length int
	rcvBuf := make([]byte, 128)
	timeout := make(chan struct{})
	go func() {
		length, err = fs.sockClient.Read(rcvBuf)
		if err != nil {
			logging.Get().Error().Msgf("read unix socket response data failed, %v", err)
			return
		}
		timeout <- struct{}{}
	}()

	select {
	case <-time.After(time.Second * 2):
		length = 0

	case <-timeout:
		//logging.Get().Info().Msgf("receive data : %v", string(rcvBuf[:length]))
		var pInfo daemon.ProcessInfo
		err = json.Unmarshal(rcvBuf[:length], &pInfo)
		if err != nil {
			return nil, errors.Errorf("json unmarshal with setns process response data failed, %v", err)
		}
		//
		return &pInfo, nil
	}

	return nil, errors.Errorf("read udp response timeout")
}

func (fs *FlowSession) GetContainerProcessName(addrType uint8, res *daemon.K8sResData, tuple *daemon.FiveTuple) (*daemon.ProcessInfo, error) {

	for _, containerData := range res.ContainerInfo {
		//logging.Get().Info().Msgf("get pid : %v, ns : %v, pod name : %v, %+v", pid, namespace, podname, *tuple)
		netInfo := &daemon.PidAssociateMnt{
			Pid:       containerData.ContainerPid,
			AddrType:  addrType,
			TupleInfo: *tuple,
		}
		//get process
		pInfo, err := fs.GetProcessName(netInfo)
		if err != nil {
			logging.Get().Warn().Msgf("get process failed, namespace : %v, pod name : %v, tuple : %+v, error : %v", res.Namespace, res.PodName, *tuple, err)
			continue
		}
		//container name
		pInfo.ContainerName = containerData.ContainerName
		//
		if pInfo.Status != daemon.MATCH_SUCC {
			if len(res.ContainerInfo) > 1 {
				pInfo.ProcName = "unknown"
				pInfo.ContainerName = "unknown"
				pInfo.Pid = 0
			}
		} else {
			if pInfo.Pid == 0 {
				continue
			}
		}

		return pInfo, nil
	}

	return nil, errors.Errorf("container error, namespace : %v, pod name : %v, tuple : %+v", res.Namespace, res.PodName, *tuple)
}

func (fs *FlowSession) GetContainerInfo(netRes *model.TensorNetworkFlow, src, dst *daemon.K8sResData, addr *daemon.FiveTuple) (bool, error) {
	//filter dns
	if addr.SrcPort == 53 || addr.DstPort == 53 {
		return false, nil
	}

	if src != nil {
		pinfo, err := fs.GetContainerProcessName(daemon.SND_ADDR, src, addr)
		if err != nil {
			return false, errors.Errorf("get src container process name failed, %v", err)
		}
		netRes.SrcProcess = pinfo.ProcName
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
				return false, errors.Errorf("get dst container process name failed, %v", err)
			}
			//process timeout
			pinfo.Timeout = time.Now().Unix()
			//save process information
			dst.ListenPorts[key] = pinfo
			netRes.DstProcess = pinfo.ProcName
			netRes.DstContainerName = pinfo.ContainerName
			netRes.DstPid = pinfo.Pid
		} else {
			netRes.DstProcess = process.ProcName
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
	for nsData := range fs.nsDataChan {
		err := fs.ProcSessionData(&nsData)
		if err != nil {
			logging.Get().Error().Msgf("get container info failed, %v.", err)
		}
	}
}

func (fs *FlowSession) PutNetSession(nlType uint8, origin, reply *daemon.FiveTuple) {
	nsData := daemon.NetSessionLink{
		NlType: nlType,
		Origin: *origin,
		Reply:  *reply,
	}

	timer := time.NewTimer(100 * time.Millisecond)
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

func (fs *FlowSession) filterUnusedSession(addr *daemon.FiveTuple) bool {
	if addr.SrcIp == "127.0.0.1" || addr.DstIp == "127.0.0.1" {
		return false
	}

	if addr.SrcIp == fs.hostIP || addr.DstIp == fs.hostIP {
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
	//filter local lo address
	ok := fs.filterUnusedSession(&netSession.Origin)
	if !ok {
		return nil
	}
	//
	switch netSession.NlType {
	case NFCT_T_NEW:
		fs.SaveNetLinkData(netSession)
		return nil
	case NFCT_T_UPDATE, NFCT_T_TIMEOUT:
		fs.DeleteNetLinkData(netSession)
	default:
		return nil
	}
	//match pod information
	src, err := fs.k8sResInfos.GetK8sResData(netSession.Origin.SrcIp)
	dst, dstErr := fs.k8sResInfos.GetK8sResData(netSession.Reply.SrcIp)
	if err != nil && dstErr != nil {
		logging.Get().Warn().Msgf("query k8s resource failed. %+v", *netSession)
		return err
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
	}
	//get dst resource
	if dst != nil {
		netData.DstOwnerName = dst.OwnerName
		netData.DstKind = dst.Kind
		netData.DstNamespace = dst.Namespace
		netData.DstPodName = dst.PodName
	}
	//dst ip address
	netData.DstPort = netSession.Reply.SrcPort
	//network flow time
	netData.CreatedAt = time.Now()
	netData.UpdatedAt = time.Now()
	netData.Status = int(netSession.NlType)
	netData.Proto = NetProtoConvert(netSession.Origin.Proto)
	clusterKey, ok := fs.clusterManager.ClusterKey()
	if !ok {
		clusterKey = "default"
	}
	netData.SrcCluster = clusterKey
	netData.DstCluster = clusterKey
	//five tuple
	netAddr := &daemon.FiveTuple{
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
	//
	switch netSession.NlType {
	case NFCT_T_UPDATE: //update event
		//get container info
		state, err = fs.GetContainerInfo(netData, src, dst, netAddr)
		if err != nil {
			logging.Get().Error().Msgf("get container info failed, %v.", err)
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
	//if netSession.Origin.DstPort != 53 && netSession.Origin.DstPort != 8801 {
	//	logging.Get().Info().Msgf("%+v, %+v", *netSession, *netData)
	//}
	//post net flow
	return fs.submitter.Submit(context.Background(), netData)
}

func (fs *FlowSession) conntrackInitList(ctx context.Context) error {
	nfct, err := ct.Open(&ct.Config{})
	if err != nil {
		return errors.Errorf("conntrack open faied, %v", err)
	}

	defer nfct.Close()

	// Get all IPv4 entries of the expected table.
	sessions, err := nfct.Dump(ct.Conntrack, ct.IPv4)
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
		fs.PutNetSession(NFCT_T_UPDATE, origin, reply)
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
		fs.PutNetSession(nfType, origin, reply)

	case IPCTNL_MSG_CT_DELETE:
		nfType = NFCT_T_DESTROY
		logging.Get().Warn().Msgf("this netlink msg type is error, %v, %v, %v.", header.Type, nlType, nfType)

	default:
		logging.Get().Warn().Msgf("this netlink msg type is error, %v, %v.", header.Type, nlType)
	}

	return nil
}
