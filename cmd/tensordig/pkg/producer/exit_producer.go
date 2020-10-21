package producer

import (
	bpf "github.com/iovisor/gobpf/bcc"
	log "github.com/sirupsen/logrus"
)

const exitCode = `
	typedef struct {event_info_t event_info; u64 error_code;} exit_data;
	typedef struct {u64 __unused__; int __syscall_nr; long error_code;} exit_args;
	int process_exit(exit_args *ctx) {
		struct task_struct *task = (typeof(task))bpf_get_current_task();
		u64 tgid_pid = bpf_get_current_pid_tgid();
		u64 gid_uid = bpf_get_current_uid_gid();
		u32 pid = tgid_pid >> 32;
		u32 tid = tgid_pid;
		// struct fdArray *fds = sf_multi_lookup(&pid);
		char event_name[] = "exit";
		exit_data d = {
			.event_info = {
				.pid = tgid_pid >> 32,
				.tid = tgid_pid,
				.ts = bpf_ktime_get_ns(),
				.uid = gid_uid,
				.gid = gid_uid >> 32,
				.ptid = task->real_parent->pid,
				.ptgid = task->real_parent->tgid,
			},
		};
		
		// Clear cache when main thread exit.
		if (pid == tid){
			sf_multi_delete(&pid);
		}

		if (pid == tid) {
			bpf_probe_read(&d.event_info.procname, sizeof(d.event_info.procname), (void *)task->comm);
			bpf_probe_read(&d.event_info.event_name, sizeof(d.event_info.event_name), (void *)event_name);
			events_output.perf_submit(ctx, &d, sizeof(d));
		}
		return 0;
	}
`

type ExitProducer struct {
	Syscall string
}

func NewExitProducer() *ExitProducer {
	return &ExitProducer{
		Syscall: "exit",
	}
}

func (p *ExitProducer) Init(module *bpf.Module) {
	fd, err := module.LoadTracepoint("process_exit")
	if err != nil {
		log.Fatalf("Could not load tracepoint: process_exit Error: %s\n", err)
	}
	err = module.AttachTracepoint("sched:sched_process_exit", fd)
}

func (p *ExitProducer) GetName() *string {
	return &p.Syscall
}
