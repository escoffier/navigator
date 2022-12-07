package netflow

import (
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"io/ioutil"
	"syscall"
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
}

// create conntrack socket
func (ct *ConntrackTools) CreateConntrackSocket() error {
	if ct.Groups == 0 {
		return errors.Errorf("conntrack's groups is error, now groups : %v", ct.Groups)
	}

	nlPid := SOCKET_AUTOPID

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if err != nil {
		return errors.Errorf("create conntrack socket failed, %v", err)
	}

	skAddr := &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: ct.Groups,
		Pid:    uint32(nlPid),
	}
	//bind socket address
	err = unix.Bind(fd, skAddr)
	if err != nil {
		return errors.Errorf("bind socket address netlink failed, %v", err)
	}
	//save socket fd
	ct.SocketFd = fd

	return nil
}

// close conntrack socket
func (ct ConntrackTools) Close() {
	if ct.SocketFd > 0 {
		unix.Close(ct.SocketFd)
	}
}

func (ct ConntrackTools) SetConntrackAcct(path, acctValue string) error {
	if path == "" {
		path = "/proc/sys/net/netfilter/nf_conntrack_acct"
	}

	err := ioutil.WriteFile(path, []byte(acctValue), 0644) // not sure about permissions
	if err != nil {
		return errors.Errorf("set conntrack acct failed, acctValue : %s, path : %s, error : %v", acctValue, path, err)
	}

	return nil
}

func (ct ConntrackTools) HeaderConvert(hdr *syscall.NlMsghdr) *NlMsgHdr {
	return &NlMsgHdr{
		Len:   hdr.Len,
		Type:  hdr.Type,
		Flags: hdr.Flags,
		Seq:   hdr.Seq,
		Pid:   hdr.Pid,
	}
}

func (ct ConntrackTools) RunConntrackEvent(onFlowFunc CtEventCallback) error {
	if onFlowFunc == nil {
		return errors.Errorf("need process flow function")
	}

	buf := make([]byte, RECEIVE_BUFFER_SIZE)

	for {
		length, _, _, _, err := unix.Recvmsg(ct.SocketFd, buf, nil, 0)
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
			err = onFlowFunc(ct.HeaderConvert(&msg.Header), flow)
			if err != nil {
				log.Errorf("OnFlowFunc callback failed, %v.", err)
				return err
			}
		}
	}
}
