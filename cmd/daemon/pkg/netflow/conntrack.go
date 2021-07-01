package netflow

import (
	"fmt"

	"io/ioutil"

	"golang.org/x/sys/unix"
)

const (
	SOCKET_AUTOPID      = 0
	RECEIVE_BUFFER_SIZE = 65536

	NF_NETLINK_CONNTRACK_NEW         = 0x00000001
	NF_NETLINK_CONNTRACK_UPDATE      = 0x00000002
	NF_NETLINK_CONNTRACK_DESTROY     = 0x00000004
	NF_NETLINK_CONNTRACK_EXP_NEW     = 0x00000008
	NF_NETLINK_CONNTRACK_EXP_UPDATE  = 0x00000010
	NF_NETLINK_CONNTRACK_EXP_DESTROY = 0x00000020
)

func conntrackAcctInit() (err error) {
	// path := "/proc/sys/net/netfilter/nf_conntrack_acct"
	// /host/proc is mounted from host
	// TODO: should be command line arg
	path := "/host/proc/sys/net/netfilter/nf_conntrack_acct"

	accValue := "0" // TODO: WTF shouldn't it be 1?

	err = ioutil.WriteFile(path, []byte(accValue), 0644) // not sure about permissions
	if err != nil {
		return fmt.Errorf("Failed to write to file at %s: %w", path, err)
	}

	return nil
}

func newConntrackHandle(nlGroups int) (int, error) {
	nlPid := SOCKET_AUTOPID

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if err != nil {
		return fd, err
	}

	sa := &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: uint32(nlGroups),
		Pid:    uint32(nlPid),
	}

	if err := unix.Bind(fd, sa); err != nil {
		err := unix.Close(fd)
		return fd, err
	}

	return fd, nil
}
