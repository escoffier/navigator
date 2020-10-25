package producer

import (
	"C"
	"strings"

	"gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/utils"

	"fmt"

	bpf "github.com/iovisor/gobpf/bcc"
	log "github.com/sirupsen/logrus"
)

const syscallBasicProg string = `
#include <uapi/linux/ptrace.h>
#include <bcc/proto.h>
#include<linux/sched.h>
#include<linux/nsproxy.h>
#include<linux/pid_namespace.h>
#include<linux/cred.h>
#include<net/inet_sock.h>
#include<linux/net.h>
#include<linux/stat.h>
#include<linux/fdtable.h>
#include<linux/fs.h>
#include<linux/kdev_t.h>
#include<uapi/linux/stat.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/path.h>
#include <linux/sched.h>
#include <linux/slab.h>

// sf: sentisive file. key is tgid_tid, value is opened fd.
struct fdArray {
	u32 fds[8];
	u32 read_count[8];
	u32 write_count[8];
};
BPF_HASH(sf0, u32, struct fdArray);
BPF_HASH(sf1, u32, struct fdArray);
BPF_HASH(sf2, u32, struct fdArray);
BPF_HASH(sf3, u32, struct fdArray);
BPF_HASH(sf4, u32, struct fdArray);
BPF_HASH(sf5, u32, struct fdArray);
BPF_HASH(sf6, u32, struct fdArray);
BPF_HASH(sf7, u32, struct fdArray);
BPF_PERF_OUTPUT(events_output);

static u8 sf_multi_exist(u32 *key) {
	u8 result = 0;
	if (sf0.lookup(key)) result += 1<<0;
	if (sf1.lookup(key)) result += 1<<1;
	if (sf2.lookup(key)) result += 1<<2;
	if (sf3.lookup(key)) result += 1<<3;
	if (sf4.lookup(key)) result += 1<<4;
	if (sf5.lookup(key)) result += 1<<5;
	if (sf6.lookup(key)) result += 1<<6;
	if (sf7.lookup(key)) result += 1<<7;
	return result;
}

static struct fdArray* sf_multi_lookup(int idx, u32 *key) {
	idx = idx/256;
	switch (idx){
		case 0: return sf0.lookup(key); break;
		case 1: return sf1.lookup(key); break;
		case 2: return sf2.lookup(key); break;
		case 3: return sf3.lookup(key); break;
		case 4: return sf4.lookup(key); break;
		case 5: return sf5.lookup(key); break;
		case 6: return sf6.lookup(key); break;
		case 7: return sf7.lookup(key); break;
		default: return NULL; break;
	}
}

static struct fdArray* sf_multi_lookup_or_try_init(int idx, u32 *key, struct fdArray* val) {
	idx = idx/256;
	switch (idx){
		case 0: return sf0.lookup_or_try_init(key, val); break;
		case 1: return sf1.lookup_or_try_init(key, val); break;
		case 2: return sf2.lookup_or_try_init(key, val); break;
		case 3: return sf3.lookup_or_try_init(key, val); break;
		case 4: return sf4.lookup_or_try_init(key, val); break;
		case 5: return sf5.lookup_or_try_init(key, val); break;
		case 6: return sf6.lookup_or_try_init(key, val); break;
		case 7: return sf7.lookup_or_try_init(key, val); break;
		default: return NULL; break;
	}
}

static void sf_multi_update(int idx, u32 *key, struct fdArray* val) {
	idx = idx/256;
	switch (idx){
		case 0: sf0.update(key, val); break;
		case 1: sf1.update(key, val); break;
		case 2: sf2.update(key, val); break;
		case 3: sf3.update(key, val); break;
		case 4: sf4.update(key, val); break;
		case 5: sf5.update(key, val); break;
		case 6: sf6.update(key, val); break;
		case 7: sf7.update(key, val); break;
		default: break;
	}
	return;
}

static void sf_multi_delete(u32 *key) {
	sf0.delete(key);
	sf1.delete(key);
	sf2.delete(key);
	sf3.delete(key);
	sf4.delete(key);
	sf5.delete(key);
	sf6.delete(key);
	sf7.delete(key);
	return;
}

typedef struct {
	char event_name[16]; // len=16
	u64 ts; // len=24
	u32 pid; // len=28
	u32 tid; // len=32
	u32 gid; // len=36
	u32 uid; // len=40
	u32 euid; // len=44
	u32 egid; // len=48
	u32 major; // len=52
	u32 minor; // len=56
	u32 nsid; // len=60
	u32 is_sock[5]; // len=80
	u32 sports[5]; // len=100 // [in, out, err]. For syscall, 3 and 4 represent fd port. For net, 3 represent port.
	u32 dports[5]; // len=120
	u32 saddrs[5]; // len=140
	u32 daddrs[5]; // len=160
	u64 inodes[5]; // len=200
	u32 ptid; // len=204
	u32 ptgid; // len=208
	char procname[TASK_COMM_LEN]; // 224
	u32 netns; // len=228
	u32 protos[5]; // familiy << 16 | type  len=248
	long ret; // len=256
} event_info_t;

// perf_exit_arg
typedef struct {
	u64 __unused__;
	int __syscall_nr;
	long ret;
} ret_t;

static inline int strCmp(char *a, char *b, int ai, int bi, int l) {
	for (int i=0; i<l; i++) {
		if ((a[ai+i] == 0x00 && b[bi+i] != 0x00) || (a[ai+i] != 0x00 && b[bi+i] == 0x00) || a[ai+i] != b[bi+i]) {
			return 0;
		}
	}
	return 1;
}

static inline int strEqualTo(char *target, char *str) {
	return strCmp(target, str, 0, 0, strlen(target)+1) == 1;
}

static inline int strNotEqualTo(char *target, char *str) {
	return strCmp(target, str, 0, 0, strlen(target)+1) == 0;
}

static inline int strStartsWith(char *pre, char *str) {
	return strCmp(pre, str, 0, 0, strlen(pre)) == 1;
}

static inline int strEndsWith(char *post, char *str) {
    int length=strlen(post);
	return strCmp(post, str, 0, strlen(str)-length, length+1) == 1;
}

static inline int andIs(long a, long b, long c) {
	return (a & b) == c;
}

static inline int andIsNot(long a, long b, long c) {
	return (a & b) != c;
}

static inline int orIs(long a, long b, long c) {
	return (a | b) == c;
}

static inline int orIsNot(long a, long b, long c) {
	return (a | b) != c;
}

static inline int xorIs(long a, long b, long c) {
	return (a ^ b) == c;
}

static inline int xorIsNot(long a, long b, long c) {
	return (a ^ b) != c;
}
`
const syscallTemplate string = `
	// perf_data
	%s

	// perf_enter_arg
	%s

	// sys_call_type_args
	BPF_HASH(start_%s, u64, %s, 1);

	// perf_enter_arg
	int syscall_enter_%s(%s *ctx) {
		// sys_call_type_args
		u64 pid = bpf_get_current_pid_tgid();
		char name[] = "%s";
		%s d = {};
		struct task_struct *ts = (struct task_struct *)bpf_get_current_task();
		bpf_probe_read(&d.event_info.procname, sizeof(d.event_info.procname), (void *)ts->comm);
		bpf_probe_read(&d.event_info.event_name, sizeof(d.event_info.event_name), (void *)name);

		// [#146] Not sure about specific version here. I just know that it doesn't work on 3.10.0
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,0,0)
		d.event_info.nsid = 0;
#else
		u64 curpidns = (u64)ts->nsproxy->pid_ns_for_children->ns.inum;
		d.event_info.nsid = curpidns;
#endif

		d.event_info.ts = bpf_ktime_get_ns();
		u64 gid_uid = bpf_get_current_uid_gid();
		d.event_info.pid = pid >> 32;
		d.event_info.tid = pid;
		d.event_info.gid = gid_uid >> 32;
		d.event_info.uid = gid_uid;
		d.event_info.ptid = ts->real_parent->pid;
		d.event_info.ptgid = ts->real_parent->tgid;
		char *argv;
		// assign value
		%s

		// ealy fd info. Like close, we need to hook it in the syscall enter rather than exit.
		%s

out:
		// Write data to BPF_MAP
		start_%s.update(&pid, &d);
		return 0;
	}

	int syscall_exit_%s(ret_t *ctx) {
		u64 pid = bpf_get_current_pid_tgid();
		%s *data = start_%s.lookup(&pid);
		if (data == 0) {
			return 0;
		}
		%s d = *data;
		// d.event_info.ts = bpf_ktime_get_ns();
		int flag = 0; 
		%s
		if (flag == 1){
			d.event_info.ret = ctx->ret;

			struct task_struct *ts = (struct task_struct *)bpf_get_current_task();
			d.event_info.euid = ts->real_cred->euid.val;
			d.event_info.egid = ts->real_cred->egid.val;

			// 0,1,2 fd information here
			struct file **fs = ts->files->fdt->fd;
			if (fs == 0){
				return 0;
			}

			struct file *f;
			umode_t m; 
			dev_t dev; 
			u32 sport;
			u32 dport;
			// inputFdCode
			%s
			dev = f->f_inode->i_rdev;
			d.event_info.major = MAJOR(dev);
			d.event_info.minor = MINOR(dev);
			// outputFdCode
			%s
			// errorFdCode
			%s

			bool sffd = false;
			u8 fd_exist = sf_multi_exist(&d.event_info.pid);
			// fd used Assign and update fd to sf table
			%s
			// fdCreator code, update fd to sf table.
			%s
			
			if (sffd){
				events_output.perf_submit(ctx, &d, sizeof(d));
			}
	    }
		start_%s.delete(&pid);
		return 0;
	}
`

const fdAssignCode = `
	f = fs[%s];
	m = f->f_inode->i_mode;
	d.event_info.inodes[%d] = f->f_inode->i_ino;
	if (S_ISSOCK(m)) {
		struct sock *sk = ((struct socket *)f->private_data)->sk;
		if (sk->__sk_common.skc_family == AF_INET) {
			d.event_info.is_sock[%d] = 1;
			struct inet_sock *inet = (struct inet_sock *)sk;
			sport = inet->inet_sport;
			dport = inet->inet_dport;
			d.event_info.sports[%d] = ntohs(sport);
			d.event_info.dports[%d] = ntohs(dport);
			d.event_info.saddrs[%d] = inet->inet_rcv_saddr;
			d.event_info.daddrs[%d] = inet->inet_daddr;
		}
	} else if (S_ISFIFO(m)){
		d.event_info.is_sock[%d] = 2;
	} else if (S_ISREG(m)) {
		d.event_info.is_sock[%d] = 3;
	} else if (S_ISDIR(m)) {
		d.event_info.is_sock[%d] = 4;
	}
`

func fdAssignCodeGen(fdTableOffset string, outputOffset int) string {
	return fmt.Sprintf(fdAssignCode, fdTableOffset,
		outputOffset, outputOffset, outputOffset, outputOffset, outputOffset,
		outputOffset, outputOffset, outputOffset, outputOffset)
}

//SyscallProducer produce syscall data
type SyscallProducer struct {
	Syscall     string
	Filters     []FilterT
	FilterLogic string
}

func NewSyscallProducer(producerInfo *ProducerInfoT) *SyscallProducer {
	return &SyscallProducer{
		Syscall:     producerInfo.ProducerName,
		Filters:     producerInfo.ProducerFilters,
		FilterLogic: producerInfo.FilterLogic,
	}
}

func (p *SyscallProducer) Init(module *bpf.Module) {
	// load program to module
	enterFd, err := module.LoadTracepoint("syscall_enter_" + p.Syscall)
	if err != nil {
		log.Fatalf("Could not load tracepoint: syscall_enter of syscall %s. Error: %s\n", strings.ToUpper(p.Syscall), err)
	}
	exitFd, err := module.LoadTracepoint("syscall_exit_" + p.Syscall)
	if err != nil {
		log.Fatalf("Could not load tracepoint: syscall_exit of syscall %s. Error: %s\n", strings.ToUpper(p.Syscall), err)
	}

	// attach program to sys_call
	enterTracepoint := "syscalls:sys_enter_" + p.Syscall
	err = module.AttachTracepoint(enterTracepoint, enterFd)
	if err != nil {
		log.Fatalf("Could not attach to enter tracepoint of syscall %s. Error: %s\n", strings.ToUpper(p.Syscall), err)
	}
	exitTracepoint := "syscalls:sys_exit_" + p.Syscall
	err = module.AttachTracepoint(exitTracepoint, exitFd)
	if err != nil {
		log.Fatalf("Could not attach to exit tracepoint of syscall %s. Error: %s\n", strings.ToUpper(p.Syscall), err)
	}

	// // create table
	// p.Table = bpf.NewTable(module.TableId("events_"+p.Syscall), module)

	// // create channel to receive from the bpf perf
	// p.byteChan = make(chan []byte)

	// // Create perMap from table and channel
	// p.PerfMap, err = bpf.InitPerfMap(p.Table, p.byteChan)
	// if err != nil {
	// 	log.Fatalf("Counld not create perMap of syscall %s. Error: %s\n", strings.ToUpper(p.Syscall), err)
	// }

	// if err != nil {
	// 	log.Fatalf("Attach tracepoint of syscall %s failed. Error: %s\n", strings.ToUpper(p.Syscall), err)
	// }

}

func (p *SyscallProducer) getFieldsAbbr() map[string]string {
	return utils.GetFieldsAbbr(&p.Syscall)
}

func (p *SyscallProducer) GetName() *string {
	return &p.Syscall
}
