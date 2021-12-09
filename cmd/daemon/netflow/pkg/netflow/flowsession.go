package netflow

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"
	"sync"
	"time"

	ct "github.com/florianl/go-conntrack"
	"github.com/go-redis/redis/v8"
	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/netflow/pkg/docker"
	"gitlab.com/piccolo_su/vegeta/pkg/daemon"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type ClusterManager interface {
	ClusterKey() (string, bool)
}

type FlowSession struct {
	CtFlow         ConntrackTools
	netNs          *docker.NsenterData
	hostIP         string
	k8sRes         *K8sResClient
	url            string
	clusterManager ClusterManager
	submitter      *Submitter
	NsLock         sync.Mutex
	NsDataQue      []*daemon.NetSessionLink
	redisClient    *redis.Client
	conflictKey    map[uint32]int64
}

func SessionToFiveTuple(data *ct.Con, proto uint8) (*daemon.FiveTuple, *daemon.FiveTuple) {
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

func NfTypeToString(nfType uint8) string {
	switch nfType {
	case NFCT_T_NEW:
		return "NEW"
	case NFCT_T_UPDATE:
		return "UPDATE"
	case NFCT_T_DESTROY:
		return "DESTROY"
	default:

	}
	return "UNKNOWN"
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

func AllowTcpState(flow *ConntrackFlow, state uint8) bool {
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

func NewFlowSession(k8sClient *K8sResClient, clusterManager ClusterManager) (*FlowSession, error) {

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
	//
	netNs, err := docker.DockerNewClient(k8sClient.k8sClient)
	if err != nil {
		return nil, errors.Errorf("new docker client failed, %v", err)
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

	consoleUrl := os.Getenv("CONSOLE_ADDR")
	if consoleUrl == "" {
		return nil, errors.Errorf("cluster's url is nil")
	}

	url := fmt.Sprintf("%s/internal/platform/networkTopo/topologies", consoleUrl)

	fs := FlowSession{
		CtFlow:         ctFlow,
		netNs:          netNs,
		hostIP:         myHostIP,
		k8sRes:         k8sClient,
		clusterManager: clusterManager,
		url:            url,
		NsDataQue:      make([]*daemon.NetSessionLink, 0),
		redisClient:    redisClient,
		conflictKey:    make(map[uint32]int64, 0),
		submitter:      NewSubmitter(1*time.Minute, GetSubmitFunc(url)),
	}

	return &fs, nil
}

func (fs *FlowSession) Start(ctx context.Context) {
	//crontab check session
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
			}
		}()
		//init session
		err := fs.InitSession(ctx)
		if err != nil {
			logging.GetLogger().Error().Msgf("init session failed, %v.", err)
		}
	}()

	//handle queue data
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
			}
		}()
		//process session
		fs.ProcSessionQueData()
	}()

	//listen conntrack event
	err := fs.CtFlow.RunConntrackEvent(fs.onFlowCallback)
	if err != nil {
		logging.GetLogger().Error().Msgf("process conntrack event failed, %v.", err)
	}
}

func (fs *FlowSession) Close() {
	if fs.netNs != nil {
		fs.netNs.Close()
	}
	//close conntrack resource
	fs.CtFlow.Close()
}

func (fs *FlowSession) FilterConflictKey(flow *model.TensorNetworkFlow) bool {
	flag := false
	filterCondition := []uint16{5432}
	for i := 0; i < len(filterCondition); i++ {
		if flow.DstPort == filterCondition[i] {
			flag = true
			break
		}
	}

	if !flag {
		return false
	}

	key := flow.CreateConflictKey()
	nowtime := time.Now().Unix()

	timestamp, ok := fs.conflictKey[key]
	if ok {
		if nowtime-timestamp < 120 {
			return true
		}
	}
	//free map and create new map
	if len(fs.conflictKey) > 2000 {
		fs.conflictKey = make(map[uint32]int64, 0)
	}
	//add key to map
	fs.conflictKey[key] = nowtime

	return false
}

func (fs *FlowSession) PrintNetFlowLog(flow *model.TensorNetworkFlow) {
	//print log
	logging.GetLogger().Info().Msgf("%v", *flow)
}

func (fs *FlowSession) GetContainerProcessName(addrType uint8, namespace, podname, nodeIP string, tuple *daemon.FiveTuple) (string, string, error) {
	containerIds, err := fs.netNs.GetPodContainerID(namespace, podname, nodeIP)
	if err != nil {
		return "", "", errors.Errorf("get pod container id failed, %v", err)
	}

	var pid int
	var name string

	for containerId, containerName := range containerIds {
		//get pid
		pid, err = fs.netNs.GetContainerPid(containerId)
		if err != nil {
			logging.GetLogger().Error().Msgf("get container pid failed, namespace : %v, pod name : %v, tuple : %+v, error : %v", namespace, podname, *tuple, err)
			continue
		}
		//logging.GetLogger().Info().Msgf("get pid : %v, ns : %v, pod name : %v, %+v", pid, namespace, podname, *tuple)

		netInfo := &daemon.PidAssociateMnt{
			Pid:       pid,
			AddrType:  addrType,
			TupleInfo: *tuple,
		}
		//get process
		name, err = fs.netNs.GetProcessName(netInfo)
		if err != nil {
			logging.GetLogger().Warn().Msgf("get process name failed,namespace : %v, pod name : %v, tuple : %+v, error : %v", namespace, podname, *tuple, err)
			continue
		}

		if len(containerName) == 0 || len(name) == 0 {
			return "", "", errors.Errorf("get name failed, container name : %v, process name : %v", containerName, name)
		}

		return containerName, name, nil
	}

	return "", "", errors.Errorf("get container id failed, namespace : %v, pod name : %v, tuple : %+v", namespace, podname, *tuple)
}

func (fs *FlowSession) GetContainerInfo(netRes *model.TensorNetworkFlow, podInfo *daemon.NetAssocPod) (bool, error) {
	if podInfo.NetAddr.SrcPort == 53 || podInfo.NetAddr.DstPort == 53 {
		return true, nil
	}

	if podInfo.SrcNodeIp == fs.hostIP {
		containerName, name, err := fs.GetContainerProcessName(daemon.SND_ADDR, netRes.SrcNamespace, podInfo.SrcPodName, podInfo.SrcNodeIp, podInfo.NetAddr)
		if err != nil {
			return false, errors.Errorf("get src container process name failed, %v", err)
		}
		netRes.SrcProcess = name
		netRes.SrcContainerName = containerName
		//
		if podInfo.DstNodeIp != fs.hostIP {
			return RedisSaveOrUpdate(fs.redisClient, daemon.SND_ADDR, netRes)
		}
	}

	if podInfo.DstNodeIp == fs.hostIP {
		containerName, name, err := fs.GetContainerProcessName(daemon.RCV_ADDR, netRes.DstNamespace, podInfo.DstPodName, podInfo.DstNodeIp, podInfo.NetAddr)
		if err != nil {
			return false, errors.Errorf("get dst container process name failed, %v", err)
		}
		netRes.DstProcess = name
		netRes.DstContainerName = containerName
		//
		return RedisSaveOrUpdate(fs.redisClient, daemon.RCV_ADDR, netRes)
	}

	return false, nil
}

func (fs *FlowSession) ProcSessionQueData() {
	for {
		if len(fs.NsDataQue) == 0 {
			time.Sleep(1 * time.Second)
			continue
		}

		fs.NsLock.Lock()
		nsQueDataLen := len(fs.NsDataQue)
		nsData := fs.NsDataQue[:nsQueDataLen]
		fs.NsDataQue = make([]*daemon.NetSessionLink, 0)
		fs.NsLock.Unlock()
		//print debug log
		for i := 0; i < nsQueDataLen; i++ {
			if nsData[i] == nil {
				continue
			}

			err := fs.ProcSessionData(nsData[i])
			if err != nil {
				logging.GetLogger().Error().Msgf("get container info failed, %v.", err)
			}
		}
	}
}

func (fs *FlowSession) PutNetSession(nlType uint8, origin, reply *daemon.FiveTuple) {

	nsData := &daemon.NetSessionLink{
		NlType: nlType,
		Origin: origin,
		Reply:  reply,
	}

	fs.NsLock.Lock()
	fs.NsDataQue = append(fs.NsDataQue, nsData)
	fs.NsLock.Unlock()
}

func (fs *FlowSession) AllowLinkState(proto uint8, session *ct.Con) bool {
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
	return true
}

func (fs *FlowSession) ProcSessionData(netSession *daemon.NetSessionLink) error {

	ok := fs.filterUnusedSession(netSession.Origin)
	if !ok {
		return nil
	}

	pods := fs.k8sRes.K8sPods
	netData := model.TensorNetworkFlow{
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	src, err := pods.GetK8sResData(netSession.Origin.SrcIp)
	if err != nil {
		return nil
	}
	//source resource
	netData.SrcName = src.Name
	netData.SrcKind = src.Kind
	netData.SrcNamespace = src.Namespace
	//destination resource
	netData.DstPort = netSession.Origin.DstPort
	netData.Proto = NetProtoConvert(netSession.Origin.Proto)
	ckey, ok := fs.clusterManager.ClusterKey()
	if !ok {
		ckey = "default"
	}
	netData.SrcCluster = ckey
	netData.DstCluster = ckey

	dst, err := pods.GetK8sResData(netSession.Origin.DstIp)
	if err != nil {
		return nil
	}
	dstIp := netSession.Origin.DstIp
	//service
	if dst.Kind == "Service" {
		dst, err = pods.GetK8sResData(netSession.Reply.SrcIp)
		if err != nil {
			logging.GetLogger().Error().Msgf("get pods information faield by service, service ip : %s.", netSession.Origin.DstIp)
			return nil
		}
		dstIp = netSession.Reply.SrcIp
		netData.DstPort = netSession.Reply.SrcPort
	}

	netData.DstName = dst.Name
	netData.DstKind = dst.Kind
	netData.Status = int(netSession.NlType)
	netData.DstNamespace = dst.Namespace
	//print debug log
	//fs.PrintNetFlowLog(&netData)
	//put net flow information
	state := true
	if netSession.NlType == NFCT_T_UPDATE {
		//filter duplicated data
		if fs.FilterConflictKey(&netData) {
			return nil
		}

		if src.PodName == "" || dst.PodName == "" {
			logging.GetLogger().Warn().Msgf("%v, %v, %v %v", *src, *dst, *netSession.Origin, *netSession.Reply)
		}
		podInfo := &daemon.NetAssocPod{
			SrcNodeIp:    src.NodeIp,
			SrcPodName:   src.PodName,
			SrcNamespace: src.Namespace,
			DstNodeIp:    dst.NodeIp,
			DstPodName:   dst.PodName,
			DstNamespace: dst.Namespace,
			NetAddr: &daemon.FiveTuple{
				Proto:   netSession.Origin.Proto,
				SrcPort: netSession.Origin.SrcPort,
				SrcIp:   netSession.Origin.SrcIp,
				DstPort: netData.DstPort,
				DstIp:   dstIp,
			},
		}
		//create associate key
		netData.CreateAssocKey(podInfo.NetAddr)
		//get container info
		state, err = fs.GetContainerInfo(&netData, podInfo)
		if err != nil {
			logging.GetLogger().Error().Msgf("get container info failed, %v.", err)
		}
	}

	if !state {
		return nil
	}
	//create uuid
	netData.CreateUuid()
	//print log
	if netData.DstPort != 53 {
		logging.GetLogger().Info().Msgf("%+v", netData)
	}

	if netData.SrcProcess == "-" || netData.DstProcess == "-" {
		logging.GetLogger().Warn().Msgf("get process failed, %+v", netData)
		return nil
	}

	//post net flow
	return fs.submitter.Submit(context.Background(), &netData)
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

		if !fs.AllowLinkState(proto, &session) {
			continue
		}

		origin, reply := SessionToFiveTuple(&session, proto)
		fs.PutNetSession(NFCT_T_UPDATE, origin, reply)
	}

	return nil
}

func (fs *FlowSession) InitSession(ctx context.Context) error {
	logging.GetLogger().Info().Msgf("conntrack session init list.")
	//list session
	return fs.conntrackInitList(ctx)
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
			if !AllowTcpState(flow, TCP_CONNTRACK_ESTABLISHED) {
				return nil
			}
		}

		origin, reply := NetlinkToFiveTuple(flow, iptuple.Protocol)
		fs.PutNetSession(nfType, origin, reply)

	case IPCTNL_MSG_CT_DELETE:
		nfType = NFCT_T_DESTROY

	default:
		logging.GetLogger().Warn().Msgf("this netlink msg type is error, %v, %v.", header.Type, header.Type&0xff)
	}

	return nil
}
