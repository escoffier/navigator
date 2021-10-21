package netflow

import (
	"context"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"

	ct "github.com/florianl/go-conntrack"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"golang.org/x/sys/unix"
)

/*
type ipTuple struct {
	Bytes    uint64
	DstIP    net.IP
	DstPort  uint16
	Packets  uint64
	Protocol uint8
	SrcIP    net.IP
	SrcPort  uint16
}

type ConntrackFlow struct {
	FamilyType uint8
	Forward    ipTuple
	Reverse    ipTuple
	Mark       uint32
}
*/

const (
	IPCTNL_MSG_CT_NEW    = 0
	IPCTNL_MSG_CT_GET    = 1
	IPCTNL_MSG_CT_DELETE = 2
)

type ClusterManager interface {
	ClusterKey() (string, bool)
}
type FlowSession struct {
	netlinkFd      int
	hostIP         string
	krs            *K8sResClient
	url            string
	clusterManager ClusterManager
	submitter      *Submitter
}

func NewFlowSession(k8sClient *K8sResClient, clusterManager ClusterManager) (*FlowSession, error) {

	fd, err := newConntrackHandle(NF_NETLINK_CONNTRACK_NEW)
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

	consoleUrl := os.Getenv("CONSOLE_ADDR")
	if consoleUrl == "" {
		return nil, errors.Errorf("cluster's url is nil")
	}

	url := fmt.Sprintf("%s/internal/platform/networkTopo/topologies", consoleUrl)

	fs := FlowSession{
		netlinkFd:      fd,
		hostIP:         myHostIP,
		krs:            k8sClient,
		clusterManager: clusterManager,
		url:            url,
		submitter:      NewSubmitter(1*time.Minute, GetSubmitFunc(url)),
	}

	return &fs, nil
}

func (fs *FlowSession) Start(ctx context.Context) {
	//crontab check session
	go fs.InitSession(ctx)

	//listen conntrack event
	fs.startConntrackListener(ctx, fs.onFlowCallback)
}

func (fs *FlowSession) filterUnusedSession(ip interface{}) bool {
	var ipaddr net.IP

	switch ip.(type) {
	case net.IP:
		ipaddr = ip.(net.IP)
	case *net.IP:
		ipaddr = *(ip.(*net.IP))
	case string:
		ipaddr = net.ParseIP(ip.(string))
	default:
		return false
	}

	if ipaddr.Equal(net.ParseIP("127.0.0.1")) || ipaddr.Equal(net.ParseIP(fs.hostIP)) {
		return false
	}

	return true
}

func (fs FlowSession) NetProtoConvert(proto uint8) uint8 {
	switch proto {
	case unix.IPPROTO_TCP:
		return 1
	case unix.IPPROTO_UDP:
		return 2
	default:

	}
	return 0
}

func (fs *FlowSession) conntrackInitList(ctx context.Context) error {
	nfct, err := ct.Open(&ct.Config{})
	if err != nil {
		return fmt.Errorf("conntrack open faied, %v", err)
	}

	defer nfct.Close()

	// Get all IPv4 entries of the expected table.
	sessions, err := nfct.Dump(ct.Conntrack, ct.IPv4)
	if err != nil {
		return fmt.Errorf("conntrack dump failed, %v", err)
	}

	// Print out all expected sessions.
	for _, session := range sessions {
		if session.Origin == nil || session.Origin.Proto == nil || session.Origin.Proto.Number == nil {
			continue
		}

		proto := *session.Origin.Proto.Number
		if proto != unix.IPPROTO_UDP && proto != unix.IPPROTO_TCP {
			continue
		}

		// log.Infof("proto=[%2d] src=%v dst=%v sport=%v dport=%v   src=%v dst=%v sport=%v dport=%v",
		// 	*session.Origin.Proto.Number, session.Origin.Src, session.Origin.Dst, *session.Origin.Proto.SrcPort, *session.Origin.Proto.DstPort,
		// 	session.Reply.Src, session.Reply.Dst, *session.Reply.Proto.SrcPort, *session.Reply.Proto.DstPort)

		err = fs.ProcSessionData(ctx, session.Origin.Src, session.Origin.Dst, *session.Origin.Proto.DstPort, *session.Origin.Proto.Number)
		if err != nil {
			log.Errorf("proc session failed, %v.", err)
		}
	}

	return nil
}

func (fs *FlowSession) ProcSessionData(ctx context.Context, SrcIP, DstIP *net.IP, dport uint16, proto uint8) error {

	ret := fs.filterUnusedSession(SrcIP)
	ok := fs.filterUnusedSession(DstIP)
	if !ret || !ok {
		return nil
	}
	//flag := 0
	infos := fs.krs.K8sPods
	netData := model.TensorNetworkFlow{
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	srcIp := SrcIP.String()
	src, err := infos.GetK8sResData(srcIp)
	if err != nil {
		return nil
	}
	//source resource
	netData.SrcName = src.Name
	netData.SrcKind = src.Kind
	netData.SrcNamespace = src.Namespace
	//destination resource
	netData.DstPort = int(dport)
	netData.Proto = fs.NetProtoConvert(proto)
	ckey, ok := fs.clusterManager.ClusterKey()
	if !ok {
		ckey = "default"
	}
	netData.SrcCluster = ckey
	netData.DstCluster = ckey

	dstIp := DstIP.String()
	dst, err := infos.GetK8sResData(dstIp)
	if err != nil {
		return nil
	}

	if dst.Kind != "Service" {
		netData.DstName = dst.Name
		netData.DstKind = dst.Kind
		netData.DstNamespace = dst.Namespace
		netData.CreateUuid()
		return fs.submitter.Submit(ctx, &netData)
	}

	owners, tport := fs.krs.GetPodControllerFromSvc(ctx, dst.Namespace, dst.Name, int32(dport))
	for _, owner := range owners {
		netData.DstPort = int(tport)
		netData.DstName = owner.Name
		netData.DstKind = owner.Kind
		netData.DstNamespace = dst.Namespace
		netData.CreateUuid()
		return fs.submitter.Submit(ctx, &netData)
	}

	return nil
}

func (fs *FlowSession) InitSession(ctx context.Context) error {

	log.Infof("conntrack session init list.")
	//print log
	// infos := fs.krs.K8sPods
	// infos.PrintAllK8sResData()

	//list session
	return fs.conntrackInitList(ctx)
}

func (fs *FlowSession) onFlowCallback(ctx context.Context, header syscall.NlMsghdr, flow *netlink.ConntrackFlow) error {
	nlType := header.Type & 0xff
	nlType = nlType & IPCTNL_MSG_CT_DELETE
	iptuple := &flow.Forward

	/*protocol*/
	if iptuple.Protocol != unix.IPPROTO_TCP && iptuple.Protocol != unix.IPPROTO_UDP {
		return nil
	}

	/*message type*/
	switch nlType {
	case IPCTNL_MSG_CT_NEW:
		err := fs.ProcSessionData(ctx, &iptuple.SrcIP, &iptuple.DstIP, iptuple.DstPort, iptuple.Protocol)
		if err != nil {
			log.Errorf("process new session error, %v.", err)
		}

	case IPCTNL_MSG_CT_DELETE:

	default:
		log.Warnf("this netlink msg type is error, %v, %v.", header.Type, header.Type&0xff)
		return nil
	}

	return nil
}

func (fs *FlowSession) startConntrackListener(ctx context.Context, parseSession func(context.Context, syscall.NlMsghdr, *netlink.ConntrackFlow) error) {

	buf := make([]byte, RECEIVE_BUFFER_SIZE)
	for {
		length, _, _, _, err := unix.Recvmsg(fs.netlinkFd, buf, nil, 0)
		if length <= 0 {
			log.Warnf("Received conntrack message has invalid length, length = %v.", length)
			continue
		}
		if err != nil {
			log.Errorf("Failed to receive conntrack message, %v.", err)
			continue
		}

		msgs, err := syscall.ParseNetlinkMessage(buf[:length])
		if err != nil {
			log.Errorf("Failed to parse netlink message, %v.", err)
			continue
		}

		for _, msg := range msgs {
			flow := netlink.ParseRawData(msg.Data, true)
			err = parseSession(ctx, msg.Header, flow)
			// if err != nil {
			// 	log.Errorf("OnFlowFunc callback failed, %v.", err)
			// }
		}
	}
}
