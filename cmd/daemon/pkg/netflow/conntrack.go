package netflow

import (
	"context"
	"fmt"
	"github.com/containernetworking/plugins/pkg/ns"
	ct "github.com/florianl/go-conntrack"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gitlab.com/security-rd/go-pkg/logging"
	"golang.org/x/sys/unix"
	"syscall"
	"time"
)

const (
	NF_NETLINK_CONNTRACK_NEW         = 0x00000001
	NF_NETLINK_CONNTRACK_UPDATE      = 0x00000002
	NF_NETLINK_CONNTRACK_DESTROY     = 0x00000004
	NF_NETLINK_CONNTRACK_EXP_NEW     = 0x00000008
	NF_NETLINK_CONNTRACK_EXP_UPDATE  = 0x00000010
	NF_NETLINK_CONNTRACK_EXP_DESTROY = 0x00000020
)

const (
	IPCTNL_MSG_CT_NEW    = 0
	IPCTNL_MSG_CT_GET    = 1
	IPCTNL_MSG_CT_DELETE = 2
)

const (
	NLM_F_CREATE   = 0x400
	NFCT_T_NEW     = 1
	NFCT_T_UPDATE  = 2
	NFCT_T_DESTROY = 4
	NFCT_T_TIMEOUT = 8
)

const (
	SOCKET_AUTOPID            = 0
	RECEIVE_BUFFER_SIZE       = 10240
	IPS_SEEN_REPLY            = 1 << 1
	TCP_CONNTRACK_ESTABLISHED = 3
)

const (
	IPPROTO_TCP = unix.IPPROTO_TCP
	IPPROTO_UDP = unix.IPPROTO_UDP
	AF_INET     = unix.AF_INET
	AF_INET6    = unix.AF_INET6
)

type NlMsgHdr struct {
	Len   uint32
	Type  uint16
	Flags uint16
	Seq   uint32
	Pid   uint32
}

type CtEventCallback func(header *NlMsgHdr, flow *ConntrackFlow) error

type ConntrackTools struct {
	Groups   uint32
	SocketFd int
	NfCt     *ct.Nfct
	Events   chan *ct.Con
}

// create conntrack socket
func (ctt *ConntrackTools) CreateConntrackSocket() error {
	if ctt.Groups == 0 {
		return errors.Errorf("conntrack's groups is error, now groups : %v", ctt.Groups)
	}

	nlPid := SOCKET_AUTOPID

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if err != nil {
		return errors.Errorf("create conntrack socket failed, %v", err)
	}

	skAddr := &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: ctt.Groups,
		Pid:    uint32(nlPid),
	}
	//bind socket address
	err = unix.Bind(fd, skAddr)
	if err != nil {
		return errors.Errorf("bind socket address netlink failed, %v", err)
	}
	//save socket fd
	ctt.SocketFd = fd

	return nil
}

func (ctt *ConntrackTools) SetHostNs(path string) error {
	netns, err := ns.GetNS(path)
	if err != nil {
		return fmt.Errorf("get net ns failed, %+v", err)
	}
	defer netns.Close()

	err = netns.Do(func(_ ns.NetNS) error {
		/*create conntrack socket*/
		err = ctt.CreateConntrackSocket()
		if err != nil {
			return errors.Errorf("Failed to get conntrack handle")
		}
		return nil
	})

	return err
}

func (c *ConntrackTools) ConntrackListen() error {
	c.Events = make(chan *ct.Con, 5000)

	// 定义回调函数
	fn := func(con ct.Con) int {
		//logging.Get().Info().Msgf("conntrack data, %+v:%+v <--> %+v:%+v", con.Origin.Src.String(), *con.Origin.Proto.SrcPort, con.Origin.Dst.String(), *con.Origin.Proto.DstPort)

		proto := *con.Origin.Proto.Number
		if proto != IPPROTO_TCP && proto != IPPROTO_UDP {
			return 0
		}

		if proto == IPPROTO_TCP && con.ProtoInfo != nil && con.ProtoInfo.TCP != nil {
			state := *con.ProtoInfo.TCP.State
			if state != TCP_CONNTRACK_ESTABLISHED {
				return 0
			}
		}

		//logging.Get().Info().Msgf("data to chan, %+v:%+v <--> %+v:%+v", con.Origin.Src.String(), *con.Origin.Proto.SrcPort, con.Origin.Dst.String(), *con.Origin.Proto.DstPort)

		timer := time.NewTimer(200 * time.Millisecond)
		defer timer.Stop()

		select {
		case c.Events <- &con:
		case <-timer.C:
			logging.Get().Warn().Msgf("send to queue timeout: %+v:%+v <--> %+v:%+v", con.Origin.Src.String(), *con.Origin.Proto.SrcPort, con.Origin.Dst.String(), *con.Origin.Proto.DstPort)
		}

		return 0
	}

	// 开始监听连接跟踪事件
	err := c.NfCt.Register(context.Background(), ct.Conntrack, ct.NetlinkCtUpdate, fn)
	if err != nil {
		logging.Get().Error().Msgf("Could not register events: %v", err)
	}

	return err
}

func (c *ConntrackTools) ConntrackList(path string, family ct.Family) ([]ct.Con, error) {
	var ses []ct.Con
	netns, err := ns.GetNS(path)
	if err != nil {
		return ses, fmt.Errorf("get net ns failed, %+v", err)
	}
	defer netns.Close()

	err = netns.Do(func(_ ns.NetNS) error {
		/*create conntrack socket*/
		c.NfCt, err = ct.Open(&ct.Config{})
		if err != nil {
			return errors.Errorf("conntrack open faied, %v", err)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("open conntrack failed, %+v", err)
	}

	// Get all IPv4 entries of the expected table.
	ses, err = c.NfCt.Dump(ct.Conntrack, family)
	if err != nil {
		return nil, errors.Errorf("conntrack dump failed, %v", err)
	}

	return ses, err
}

// close conntrack socket
func (c ConntrackTools) Close() {
	if c.SocketFd > 0 {
		unix.Close(c.SocketFd)
	}

	if c.NfCt != nil {
		_ = c.NfCt.Close()
	}

	c.NfCt = nil
}

func (ctt ConntrackTools) HeaderConvert(hdr *syscall.NlMsghdr) *NlMsgHdr {
	return &NlMsgHdr{
		Len:   hdr.Len,
		Type:  hdr.Type,
		Flags: hdr.Flags,
		Seq:   hdr.Seq,
		Pid:   hdr.Pid,
	}
}

func (ctt ConntrackTools) RunConntrackEvent(onFlowFunc CtEventCallback) error {
	if onFlowFunc == nil {
		return errors.Errorf("need process flow function")
	}

	buf := make([]byte, RECEIVE_BUFFER_SIZE)

	for {
		length, _, _, _, err := unix.Recvmsg(ctt.SocketFd, buf, nil, 0)
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
			//parse raw data
			flow := ParseRawData(msg.Data)
			//process flow data
			err = onFlowFunc(ctt.HeaderConvert(&msg.Header), flow)
			if err != nil {
				log.Errorf("OnFlowFunc callback failed, %v.", err)
				return err
			}
		}
	}
}
