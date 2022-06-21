#include <linux/netdevice.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include "bpf_helpers.h"


#define _(P)                                                                   \
	({                                                                     \
		typeof(P) val = 0;                                             \
		bpf_probe_read_kernel(&val, sizeof(val), &(P));                \
		val;                                                           \
	})

#define bpf_printk(fmt, ...)                                                   \
	({                                                                     \
		char ____fmt[] = fmt;                                          \
		bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);     \
	})


struct proc_info {
    u32 pid;
    u8  comm[32];
} __attribute__((packed));

struct net_addr {
    u8  proto;
    u16 sport;
    u16 dport;
    u32 saddr;
    u32 daddr;
} __attribute__((packed));

struct bpf_map_def SEC("maps") tcpsock_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u64),
	.value_size = sizeof(u64),
	.max_entries = 1024,
};

struct bpf_map_def SEC("maps") netdata_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct net_addr),
	.value_size = sizeof(struct proc_info),
	.max_entries = 20480,
};

struct bpf_map_def SEC("maps") filter_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u32),
	.value_size = sizeof(u8),
	.max_entries = 128,
};

SEC("kprobe/inet_bind")
int kprobe__socket_bind(struct pt_regs *ctx)
{
    u16 type;

    struct sockaddr_in *addr = (struct sockaddr_in *)PT_REGS_PARM2(ctx);
    int addrlen = (int)PT_REGS_PARM3(ctx);
    struct socket *socket = (struct socket *)PT_REGS_PARM1(ctx);
    //addr length
    if (addrlen != sizeof(struct sockaddr_in)) {return 0;}
    //read protocol
    bpf_probe_read(&type, sizeof(type), &socket->type);
    //SOCK_STREAM = 1, SOCK_DGRAM = 2,
    switch(type)
    {
        case SOCK_STREAM:
            type = IPPROTO_TCP;
            break;
        case SOCK_DGRAM:
            type = IPPROTO_UDP;
            break;
        default:
            return 0;
    }
    //init
    struct net_addr netaddr;
    struct proc_info procinfo;
    __builtin_memset(&netaddr, 0, sizeof(netaddr));
    __builtin_memset(&procinfo, 0, sizeof(procinfo));
    //proto
    netaddr.proto = type;
    //get source address
    bpf_probe_read(&netaddr.saddr, sizeof(netaddr.saddr), &addr->sin_addr.s_addr);
    bpf_probe_read(&netaddr.sport, sizeof(netaddr.sport), &addr->sin_port);
    //ntohs
    netaddr.sport = ntohs(netaddr.sport);
    //filter invalid port
    if((netaddr.sport == 0) && (netaddr.dport == 0)) return 0;
    //get comm
    bpf_get_current_comm(&procinfo.comm, sizeof(procinfo.comm));
    //get pid
    procinfo.pid = bpf_get_current_pid_tgid() >> 32;
    //save data
    bpf_map_update_elem(&netdata_map, &netaddr, &procinfo, BPF_ANY);
    // debug log
    // bpf_printk("[bind] type : %d\n", type);
    // bpf_printk("[bind] sport : %d, dport : %d\n", netaddr.sport, netaddr.dport);
    // bpf_printk("[bind] saddr : 0x%x, daddr : 0x%x\n", netaddr.saddr, netaddr.daddr);
    // bpf_printk("[bind] pid : %lu, comm : %s\n", procinfo.pid, procinfo.comm);
    
    return 0;
}
/*
SEC("kprobe/inet_dgram_connect")
int kprobe__udp_connect(struct pt_regs *ctx)
{
    u32 saddr;
    u16 sport;
    char comm[64] = { 0 };

    struct sockaddr_in *addr = (struct sockaddr_in *)PT_REGS_PARM2(ctx);
    int addrlen = (int)PT_REGS_PARM3(ctx);

    if (addrlen != sizeof(struct sockaddr_in)) {return 0;}

    bpf_probe_read(&saddr, sizeof(saddr), &addr->sin_addr.s_addr);
    bpf_probe_read(&sport, sizeof(sport), &addr->sin_port);

    bpf_get_current_comm(&comm, sizeof(comm));
    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_printk("[udp connect] addr : 0x%x, port : %d\n", saddr, ntohs(sport));
    bpf_printk("[udp connect] pid : %lu, comm : %s\n", pid_tgid >> 32, comm);

    return 0;
}
*/
//SEC("kprobe/tcp_v4_connect")
SEC("kprobe/tcp_connect")
int kprobe__tcp_v4_connect(struct pt_regs *ctx)
{
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

	u64 skp = (u64)sk;
	u64 pid_tgid = bpf_get_current_pid_tgid();
    //add
	bpf_map_update_elem(&tcpsock_map, &pid_tgid, &skp, BPF_ANY);

	return 0;
}

SEC("kretprobe/tcp_v4_connect")
int kretprobe__tcp_v4_connect(struct pt_regs *ctx)
{
    u8 *match_filter;
	char comm[64] = { 0 };
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u64 *skp = bpf_map_lookup_elem(&tcpsock_map, &pid_tgid);
	if (skp == NULL)
    {
		return 0;
	}
    //delete
    bpf_map_delete_elem(&tcpsock_map, &pid_tgid);

	struct sock *sk;
	__builtin_memset(&sk, 0, sizeof(sk));
	sk = (struct sock *)*skp;

	struct net_addr tcpdata;
    struct proc_info procinfo;
    //init
    __builtin_memset(&tcpdata, 0, sizeof(tcpdata));
    __builtin_memset(&procinfo, 0, sizeof(procinfo));
    //proto
    tcpdata.proto = IPPROTO_TCP;
    //get address
	bpf_probe_read(&tcpdata.dport, sizeof(tcpdata.dport), &sk->sk_dport);
	bpf_probe_read(&tcpdata.sport, sizeof(tcpdata.sport), &sk->sk_num);
	bpf_probe_read(&tcpdata.daddr, sizeof(tcpdata.daddr), &sk->sk_daddr);
	bpf_probe_read(&tcpdata.saddr, sizeof(tcpdata.saddr), &sk->sk_rcv_saddr);
    //ntohs
    tcpdata.dport = ntohs(tcpdata.dport);
    //filter source address
    match_filter = bpf_map_lookup_elem(&filter_map, &tcpdata.saddr);
    if(match_filter != NULL) return 0;
    //filter dest address
    match_filter = bpf_map_lookup_elem(&filter_map, &tcpdata.daddr);
    if(match_filter != NULL) return 0;
    //lookup
    struct proc_info *value = bpf_map_lookup_elem(&netdata_map, &tcpdata);
    if(value)
    {
        bpf_printk("[tcp] data has exist! sport : %d, dport : %d\n", tcpdata.sport, tcpdata.dport);
        return 0;
    }
    //get comm
	bpf_get_current_comm(&procinfo.comm, sizeof(procinfo.comm));
    //get pid
    procinfo.pid = pid_tgid >> 32;
    //save data
    bpf_map_update_elem(&netdata_map, &tcpdata, &procinfo, BPF_ANY);
    //debug log
	// bpf_printk("[tcp] sport : %d, dport : %d\n", tcpdata.sport, tcpdata.dport);
	// bpf_printk("[tcp] pid : %lu, comm : %s\n", procinfo.pid, procinfo.comm);

	return 0;
}

SEC("kprobe/udp_sendmsg")
//SEC("kprobe/ip4_datagram_connect")
int kprobe__udp_sendmsg(struct pt_regs *ctx)
{
    u8 *match_filter;
	u64 msg_name; //pointer
    int ret;
    struct net_addr udpdata;
    struct proc_info procinfo;

#ifdef OPENSNITCH_x86_32
	struct sock *sk = (struct sock *)((ctx)->ax);
	struct msghdr *msg = (struct msghdr *)((ctx)->dx);
#else
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
#endif

    //init
	__builtin_memset(&msg_name, 0, sizeof(msg_name));
	bpf_probe_read(&msg_name, sizeof(msg_name), &msg->msg_name);
	struct sockaddr_in *usin = (struct sockaddr_in *)msg_name;
    //init
	__builtin_memset(&udpdata, 0, sizeof(udpdata));
    __builtin_memset(&procinfo, 0, sizeof(procinfo));
    //get proto
    udpdata.proto = IPPROTO_UDP;
    //get udp address
	bpf_probe_read(&udpdata.dport, sizeof(udpdata.dport), &usin->sin_port);
	if (udpdata.dport != 0)
    { //likely
		bpf_probe_read(&udpdata.daddr, sizeof(udpdata.daddr), &usin->sin_addr.s_addr);
	}
    else
    {
		//very rarely dport can be found in skc_dport
		bpf_probe_read(&udpdata.dport, sizeof(udpdata.dport), &sk->__sk_common.skc_dport);
		bpf_probe_read(&udpdata.daddr, sizeof(udpdata.daddr), &sk->__sk_common.skc_daddr);
	}
	bpf_probe_read(&udpdata.sport, sizeof(udpdata.sport), &sk->__sk_common.skc_num);
	bpf_probe_read(&udpdata.saddr, sizeof(udpdata.saddr), &sk->__sk_common.skc_rcv_saddr);
    //ntohs
    udpdata.dport = ntohs(udpdata.dport);
    //filter dns port
    if((udpdata.sport == 53) || (udpdata.dport == 53)) return 0;
    //filter source address
    match_filter = bpf_map_lookup_elem(&filter_map, &udpdata.saddr);
    if(match_filter != NULL) return 0;
    //filter dest address
    match_filter = bpf_map_lookup_elem(&filter_map, &udpdata.daddr);
    if(match_filter != NULL) return 0;
    //get pid
    procinfo.pid = bpf_get_current_pid_tgid() >> 32;
    //get comm
    bpf_get_current_comm(&procinfo.comm, sizeof(procinfo.comm));
    //save data
    ret = bpf_map_update_elem(&netdata_map, &udpdata, &procinfo, BPF_NOEXIST);
    if(ret != 0) return 0;
	//debug log
    // bpf_printk("[udp] sport : %d, dport : %d.\n", udpdata.sport, udpdata.dport);
	// bpf_printk("[udp] saddr : %u, daddr : %u.\n", udpdata.saddr, udpdata.daddr);
    // bpf_printk("[udp] save pid : %lu, comm : %s\n", procinfo.pid, procinfo.comm);
	//else nothing to do
	return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
