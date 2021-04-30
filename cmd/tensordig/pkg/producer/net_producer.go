package producer

import (
	"C"
	"bytes"
	"encoding/binary"
	"runtime/debug"
	"strings"

	log "github.com/sirupsen/logrus"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"

	bpf "gitlab.com/tensorsecurity-rd/gobpf/bcc"
)
import (
	"fmt"
	"net/http"
	"os"
	"sync"

	"gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/constant"
)

const netBasicProg string = `
// #include <net/net_namespace.h>
// #include <bcc/proto.h>
// #pragma clang diagnostic push
// #pragma clang diagnostic ignored "-Wenum-conversion"
// #include <net/inet_sock.h>
// #pragma clang diagnostic pop

// Common structure for UDP/TCP IPv4/IPv6
struct socket_event_t {
	event_info_t event_info; // 208
	u32 proto; // 212
	u32 sport; 
	u32 dport;
	u32 saddr;
	u32 daddr;
};
BPF_PERF_OUTPUT(events);
BPF_HASH(start, u64, struct sock *);
BPF_HASH(sock_map, u64, struct socket *);

// static inline struct socket_event_t socket_handle(
static int socket_handle(
	struct pt_regs *ctx, u64 pid_tgid,
	char *action, struct socket_event_t *evt, struct sock *sk) 
{
	// struct socket_event_t evt = {};
	struct inet_sock *inet = (struct inet_sock *)sk;

	// Get action 
	bpf_probe_read(&evt->event_info.event_name, sizeof(evt->event_info.event_name), (void *)action);

	// Get ts
	evt->event_info.ts = bpf_ktime_get_ns();

	// Get PID tid nsid 
	evt->event_info.pid = pid_tgid >> 32;
	evt->event_info.tid = pid_tgid;
	struct task_struct *ts = (struct task_struct *)bpf_get_current_task();

	// [#146] Not sure about specific version here. I just know that it doesn't work on 3.10.0
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,0,0)
	evt->event_info.nsid = 0;
#else
	evt->event_info.nsid = (u64)ts->nsproxy->pid_ns_for_children->ns.inum;
#endif

	bpf_get_current_comm(&evt->event_info.procname, sizeof(evt->event_info.procname));

	// Get gid uid
	u64 gid_uid = bpf_get_current_uid_gid();
	evt->event_info.gid = gid_uid >> 32;
	evt->event_info.uid = gid_uid;
	evt->event_info.euid = ts->real_cred->euid.val;
	evt->event_info.egid = ts->real_cred->egid.val;

	// Get reterun value
	long ret = PT_REGS_RC(ctx);
	evt->event_info.ret = ret;

	// Get socket IP family
	u16 family = sk->__sk_common.skc_family;
	// Get type 

	// u8 protocl = 0;
	u16 type = 0;
	// Bit field extraction. sk_gso_max_segs is defined after sk_type
	// bpf_probe_read(&protocl, 1, (void *)((long)&sk->sk_gso_max_segs) -3);
	bpf_probe_read(&type, 2, (void *)((long)&sk->sk_gso_max_segs) -2);
	evt->proto =  ((u32)family) << 16 | type;

	// Get port
	evt->sport = inet->inet_sport;
	evt->sport = ntohs(evt->sport);
	evt->dport = inet->inet_dport;
	evt->dport = ntohs(evt->dport);

	// Get network namespace id, if kernel supports it
#ifdef CONFIG_NET_NS

// [#146] Not sure about specific version here. I just know that it doesn't work on 3.10.0
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,0,0)
	evt->event_info.netns = 0;
#else
	evt->event_info.netns = sk->__sk_common.skc_net.net->ns.inum;
#endif

#else
	evt->event_info.netns = 0
#endif

	// Get IP
	if (family == AF_INET) {
		evt->saddr = inet->inet_rcv_saddr;
		evt->daddr = inet->inet_daddr;
	}
	return 0;
}

`

const socketTemplate string = `
int kprobe__%s(struct pt_regs *ctx, struct socket *sock){
	u64 pid_tgid = bpf_get_current_pid_tgid();
	sock_map.update(&pid_tgid, &sock);
	return 0;
}
`

const inetAccept string = `
int kprobe__%s(struct pt_regs *ctx, struct socket *sock, struct socket *newsock){
	u64 pid_tgid = bpf_get_current_pid_tgid();
	sock_map.update(&pid_tgid, &newsock);
	return 0;
}
`

const sockTemplate string = `
int kprobe__%s(struct pt_regs *ctx, struct sock *sk){
	u64 pid_tgid = bpf_get_current_pid_tgid();
	start.update(&pid_tgid, &sk);
	return 0;
}

`

const sockReturnTeamplate string = `
	int kretprobe__%s(struct pt_regs *ctx) {
		char action[] = "%s";
		u64 pid_tgid = bpf_get_current_pid_tgid();
		struct socket_event_t d = {};
		struct sock **skp = start.lookup(&pid_tgid);
		if (skp == 0){
			// *succeed = 0;
			// return evt;
			return -1;
		}
		struct sock *sk = *skp;
		int succeed = socket_handle(ctx, pid_tgid, action, &d, sk);
		if (succeed == 0) {
			// Filter code here.
			int flag = 0;
			%s
			if (1 == flag) {
				events.perf_submit(ctx, &d, sizeof(d));
			}
			start.delete(&pid_tgid);
		} 
		return 0;
	}
`

const socketReturn string = `
	int kretprobe__%s(struct pt_regs *ctx) {
		char action[] = "%s";
		u64 pid_tgid = bpf_get_current_pid_tgid();
		struct socket_event_t d = {};
		struct socket **skp = sock_map.lookup(&pid_tgid);
		if (skp == 0){
			return -1;
		}
		struct socket *sock = *skp;
		int succeed = socket_handle(ctx, pid_tgid, action, &d, sock->sk);
		if (succeed == 0) {
			// Filter code here.
			int flag = 0;
			%s
			if (1 == flag) {
				events.perf_submit(ctx, &d, sizeof(d));
			}
			sock_map.delete(&pid_tgid);
		} 
		return 0;
	}
`

type SocketData struct {
	EventInfo constant.EventInfoT
	Proto     uint32
	Sport     uint32
	Dport     uint32
	Saddr     uint32
	Daddr     uint32
}

type SocketProducer struct {
	PerfMap      *bpf.PerfMap
	Table        *bpf.Table
	ProbeNames   []string
	dataChan     chan constant.Data
	byteChan     chan []byte
	lostChan     chan uint64
	QuitChan     chan struct{}
	StopChan     chan struct{}
	Name         string
	Filters      [][]FilterT
	FilterLogics []string
	ConsoleAddr  string
	HTTPClient   *http.Client
}

func NewSocketProducer(producersInfo []ProducerInfoT) *SocketProducer {
	probeNames := make([]string, len(producersInfo))
	filters := make([][]FilterT, len(producersInfo))
	filterLogics := make([]string, len(producersInfo))
	for i, pif := range producersInfo {
		probeNames[i] = pif.ProducerName
		filters[i] = pif.ProducerFilters
		filterLogics[i] = pif.FilterLogic
	}
	consoleHost := os.Getenv("TENSORSEC_CONSOLE_HOST")
	consolePort := os.Getenv("TENSORSEC_CONSOLE_PORT")
	var consoleAddr = ""
	if consolePort != "" && consoleHost != "" {
		consoleAddr = fmt.Sprintf("http://%s:%s", consoleHost, consolePort)
	}

	return &SocketProducer{
		PerfMap:      nil,
		Table:        nil,
		ProbeNames:   probeNames,
		dataChan:     make(chan constant.Data, DataChanBufferSize),
		byteChan:     make(chan []byte),
		lostChan:     make(chan uint64),
		QuitChan:     make(chan struct{}),
		StopChan:     make(chan struct{}),
		Filters:      filters,
		FilterLogics: filterLogics,
		ConsoleAddr:  consoleAddr,
		HTTPClient:   &http.Client{},
	}
}

func (sp *SocketProducer) Init(module *bpf.Module) error {
	var err error
	var name strings.Builder
	name.WriteString("Nets: ")
	for _, probeName := range sp.ProbeNames {
		Kprobe, err := module.LoadKprobe("kprobe__" + probeName)
		if err != nil {
			logging.GetLogger().Error().Err(err).Str("probe", probeName).Msg("Could not load kprobe")
			return err
		}

		err = module.AttachKprobe(probeName, Kprobe, -1)
		if err != nil {
			logging.GetLogger().Error().Err(err).Str("probe", probeName).Msg("Could not attach kprobe")
			return err
		}

		Kretprobe, err := module.LoadKprobe("kretprobe__" + probeName)
		if err != nil {
			logging.GetLogger().Error().Err(err).Str("probe", probeName).Msg("Could not load kretprobe")
			return err
		}

		err = module.AttachKretprobe(probeName, Kretprobe, -1)
		if err != nil {
			logging.GetLogger().Error().Err(err).Str("probe", probeName).Msg("Could not attach kretprobe")
			return err
		}
		name.WriteString(probeName)
		name.WriteString(" ")
	}
	sp.Name = name.String()

	sp.Table = bpf.NewTable(module.TableId("events"), module)

	sp.PerfMap, err = bpf.InitPerfMap(sp.Table, sp.byteChan, sp.lostChan)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Could not init perf map")
		return err
	}
	return nil
}

func (sp *SocketProducer) process(event *constant.TotalData) {
	if (cap(sp.dataChan) - len(sp.dataChan)) > 0 {
		sp.dataChan <- event
	} else {
		<-sp.dataChan
		sp.dataChan <- event // drop the oldest element
		log.Error("Scheduler or consumer is too slow. Lost data!")
	}
}

func (sp *SocketProducer) Deserialize(wg *sync.WaitGroup) {
	for data := range sp.byteChan {
		var event SocketData
		err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event)
		if err != nil {
			log.Warnf("SocketProducer failed to decode received data: %s\n", err)
			continue
		}
		var d constant.TotalData
		d.IsSyscall = false
		d.EventInfo = event.EventInfo
		d.EventInfo.Protos[3] = event.Proto
		d.EventInfo.Sports[3] = event.Sport
		d.EventInfo.Dports[3] = event.Dport
		d.EventInfo.Saddrs[3] = event.Saddr
		d.EventInfo.Daddrs[3] = event.Daddr
		sp.process(&d)
	}
	wg.Done()
}

func (sp *SocketProducer) Start() {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Msgf("Panic : %v. stack: %s", r, debug.Stack())
			}
		}()

		sp.Deserialize(&wg)
	}()
	sp.PerfMap.Start()
	<-sp.StopChan
	sp.PerfMap.Stop()
	close(sp.byteChan)
	wg.Wait()
	sp.QuitChan <- struct{}{}
}

func (sp *SocketProducer) Stop() {
	sp.StopChan <- struct{}{}
	<-sp.QuitChan
	close(sp.dataChan)
}

func (sp *SocketProducer) GetName() *string {
	return &sp.Name
}

func (sp *SocketProducer) GetDataChan() <-chan constant.Data {
	return sp.dataChan
}

func (sp *SocketProducer) getFieldsAbbr() map[string]string {
	fieldsAbbr := map[string]string{
		"family": "integer",
		"sport":  "integer",
		"dport":  "integer",
		"saddr":  "integer",
		"daddr":  "integer",
	}
	return fieldsAbbr
}
