package falco

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
)

var (
	DefaultSyscallWhitelist = []string{
		"accept",
		"accept4",
		"access",
		"adjtimex",
		"alarm",
		"bind",
		"brk",
		"capget",
		"capset",
		"chdir",
		"chmod",
		"chown",
		"clock_adjtime",
		"clock_getres",
		"clock_gettime",
		"clock_nanosleep",
		"close",
		"connect",
		"dup",
		"dup2",
		"dup3",
		"epoll_create",
		"epoll_create1",
		"epoll_ctl",
		"epoll_pwait",
		"epoll_wait",
		"eventfd",
		"eventfd2",
		"execve",
		"exit",
		"exit_group",
		"faccessat",
		"fadvise64",
		"fallocate",
		"fchdir",
		"fchmod",
		"fchmodat",
		"fchown",
		"fchownat",
		"fcntl",
		"fcntl64",
		"fdatasync",
		"fgetxattr",
		"flistxattr",
		"flock",
		"fork",
		"fremovexattr",
		"fsetxattr",
		"fstat",
		"fstat64",
		"fstatat64",
		"fstatfs",
		"fstatfs64",
		"fsync",
		"ftruncate",
		"futex",
		"futimesat",
		"getcpu",
		"getcwd",
		"getdents",
		"getdents64",
		"getegid",
		"getegid32",
		"geteuid",
		"geteuid32",
		"getgid",
		"getgid32",
		"getgroups",
		"getitimer",
		"getpeername",
		"getpgrp",
		"getpid",
		"getppid",
		"getpriority",
		"getrandom",
		"getresgid",
		"getresgid32",
		"getresuid",
		"getresuid32",
		"getrlimit",
		"get_robust_list",
		"getrusage",
		"getsockname",
		"getsockopt",
		"get_thread_area",
		"gettid",
		"gettimeofday",
		"getuid",
		"getuid32",
		"getxattr",
		"inotify_add_watch",
		"inotify_init",
		"inotify_init1",
		"inotify_rm_watch",
		"io_cancel",
		"ioctl",
		"io_destroy",
		"io_getevents",
		"ioprio_get",
		"ioprio_set",
		"io_setup",
		"io_submit",
		"ipc",
		"kill",
		"lchown",
		"lgetxattr",
		"link",
		"linkat",
		"listen",
		"listxattr",
		"llistxattr",
		"lremovexattr",
		"lseek",
		"lsetxattr",
		"lstat",
		"lstat64",
		"madvise",
		"mkdir",
		"mkdirat",
		"mlock",
		"mlockall",
		"mmap",
		"mmap2",
		"mprotect",
		"mq_getsetattr",
		"mq_notify",
		"mq_open",
		"mq_timedreceive",
		"mq_timedsend",
		"mq_unlink",
		"mremap",
		"msgctl",
		"msgget",
		"msgrcv",
		"msgsnd",
		"msync",
		"munlockall",
		"munmap",
		"nanosleep",
		"newfstatat",
		"open",
		"openat",
		"pause",
		"pipe",
		"pipe2",
		"poll",
		"ppoll",
		"prctl",
		"pread64",
		"preadv",
		"prlimit64",
		"pselect6",
		"pwrite64",
		"pwritev",
		"read",
		"readlink",
		"readlinkat",
		"readv",
		"recvfrom",
		"recvmmsg",
		"recvmsg",
		"remap_file_pages",
		"removexattr",
		"rename",
		"renameat",
		"renameat2",
		"restart_syscall",
		"rmdir",
		"rt_sigaction",
		"rt_sigpending",
		"rt_sigprocmask",
		"rt_sigqueueinfo",
		"rt_sigreturn",
		"rt_sigsuspend",
		"rt_sigtimedwait",
		"rt_tgsigqueueinfo",
		"sched_getaffinity",
		"sched_getparam",
		"sched_get_priority_max",
		"sched_get_priority_min",
		"sched_getscheduler",
		"sched_rr_get_interval",
		"sched_setaffinity",
		"sched_setparam",
		"sched_setscheduler",
		"sched_yield",
		"seccomp",
		"select",
		"semctl",
		"semget",
		"semop",
		"sendfile",
		"sendfile64",
		"sendmmsg",
		"sendmsg",
		"sendto",
		"setfsgid",
		"setfsuid",
		"setgid",
		"setgid32",
		"setgroups",
		"setitimer",
		"setpgid",
		"setpriority",
		"setregid",
		"setresgid",
		"setresgid32",
		"setresuid",
		"setresuid32",
		"setreuid",
		"setrlimit",
		"set_robust_list",
		"setsid",
		"setsockopt",
		"set_thread_area",
		"set_tid_address",
		"setuid",
		"setuid32",
		"setxattr",
		"shmat",
		"shmctl",
		"shmdt",
		"shutdown",
		"sigaltstack",
		"signalfd",
		"signalfd4",
		"sigprocmask",
		"socket",
		"socketpair",
		"splice",
		"stat",
		"stat64",
		"statfs",
		"statfs64",
		"symlink",
		"symlinkat",
		"sync",
		"syncfs",
		"sysinfo",
		"tee",
		"tgkill",
		"timer_create",
		"timer_delete",
		"timer_getoverrun",
		"timer_gettime",
		"timer_settime",
		"timerfd_create",
		"timerfd_gettime",
		"timerfd_settime",
		"times",
		"tkill",
		"truncate",
		"ugetrlimit",
		"umask",
		"uname",
		"unlink",
		"unlinkat",
		"utime",
		"utimensat",
		"utimes",
		"vfork",
		"vmsplice",
		"wait4",
		"waitid",
		"waitpid",
		"write",
		"writev",
	}
)

var (
	// TODO: Maybe use https://docs.docker.com/engine/security/seccomp ?
	// Based on syscall_table.c from sysdig: https://fossies.org/linux/sysdig/driver/syscall_table.c
	SeccompEventsToWatch = []string{
		"accept",
		"accept4",
		"access",
		"acct",
		"add_key",
		"adjtimex",
		"alarm",
		"arch_prctl",
		"bdflush",
		"bind",
		"bpf",
		"brk",
		"capget",
		"capset",
		"chdir",
		"chmod",
		"chown",
		"chroot",
		"clock_adjtime",
		"clock_getres",
		"clock_gettime",
		"clock_nanosleep",
		"clock_settime",
		"clone",
		"close",
		"connect",
		"creat",
		"delete_module",
		"dup",
		"dup2",
		"dup3",
		"epoll_create",
		"epoll_create1",
		"epoll_ctl",
		"epoll_pwait",
		"epoll_wait",
		"eventfd",
		"eventfd2",
		"execve",
		"exit",
		"exit_group",
		"faccessat",
		"fadvise64",
		"fallocate",
		"fanotify_init",
		"fchdir",
		"fchmod",
		"fchmodat",
		"fchown",
		"fchownat",
		"fcntl",
		"fcntl64",
		"fdatasync",
		"fgetxattr",
		"finit_module",
		"flistxattr",
		"flock",
		"fork",
		"fremovexattr",
		"fsetxattr",
		"fstat",
		"fstat64",
		"fstatat64",
		"fstatfs",
		"fstatfs64",
		"fsync",
		"ftruncate",
		"futex",
		"futimesat",
		"getcpu",
		"getcwd",
		"getdents",
		"getdents64",
		"getegid",
		"getegid32",
		"geteuid",
		"geteuid32",
		"getgid",
		"getgid32",
		"getgroups",
		"getitimer",
		"getpeername",
		"getpgrp",
		"getpid",
		"getppid",
		"getpriority",
		"getrandom",
		"getresgid",
		"getresgid32",
		"getresuid",
		"getresuid32",
		"getrlimit",
		"getrusage",
		"getsockname",
		"getsockopt",
		"gettid",
		"gettimeofday",
		"getuid",
		"getuid32",
		"getxattr",
		"get_robust_list",
		"get_thread_area",
		"init_module",
		"inotify_add_watch",
		"inotify_init",
		"inotify_init1",
		"inotify_rm_watch",
		"ioctl",
		"ioprio_get",
		"ioprio_set",
		"io_cancel",
		"io_destroy",
		"io_getevents",
		"io_setup",
		"io_submit",
		"ipc",
		"kexec_load",
		"keyctl",
		"kill",
		"lchown",
		"lgetxattr",
		"link",
		"linkat",
		"listen",
		"listxattr",
		"llistxattr",
		"llseek",
		"lremovexattr",
		"lseek",
		"lsetxattr",
		"lstat",
		"lstat64",
		"madvise",
		"micore",
		"mkdir",
		"mkdirat",
		"mlock",
		"mlockall",
		"mmap",
		"mmap2",
		"mount",
		"mprotect",
		"mq_getsetattr",
		"mq_notify",
		"mq_open",
		"mq_timedreceive",
		"mq_timedsend",
		"mq_unlink",
		"mremap",
		"msgctl",
		"msgget",
		"msgrcv",
		"msgsnd",
		"msync",
		"munlockall",
		"munmap",
		"nanosleep",
		"newfstatat",
		"newselect",
		"nice",
		"olduname",
		"open",
		"openat",
		"pause",
		"perf_event_open",
		"personality",
		"pipe",
		"pipe2",
		"pivot_root",
		"poll",
		"ppoll",
		"prctl",
		"pread64",
		"preadv",
		"prlimit64",
		"process_vm_readv",
		"process_vm_writev",
		"pselect6",
		"ptrace",
		"pwrite64",
		"pwritev",
		"quotactl",
		"read",
		"readlink",
		"readlinkat",
		"readv",
		"reboot",
		"recvfrom",
		"recvmmsg",
		"recvmsg",
		"remap_file_pages",
		"removexattr",
		"rename",
		"renameat",
		"renameat2",
		"request_key",
		"restart_syscall",
		"rmdir",
		"rt_sigaction",
		"rt_sigpending",
		"rt_sigprocmask",
		"rt_sigqueueinfo",
		"rt_sigreturn",
		"rt_sigsuspend",
		"rt_sigtimedwait",
		"rt_tgsigqueueinfo",
		"sched_getaffinity",
		"sched_getparam",
		"sched_getscheduler",
		"sched_get_priority_max",
		"sched_get_priority_min",
		"sched_rr_get_interval",
		"sched_setaffinity",
		"sched_setparam",
		"sched_setscheduler",
		"sched_yield",
		"seccomp",
		"select",
		"semctl",
		"semget",
		"semop",
		"sendfile",
		"sendfile64",
		"sendmmsg",
		"sendmsg",
		"sendto",
		"setdomainname",
		"setfsgid",
		"setfsuid",
		"setgid",
		"setgid32",
		"setgroups",
		"sethostname",
		"setitimer",
		"setns",
		"setpgid",
		"setpriority",
		"setregid",
		"setresgid",
		"setresgid32",
		"setresuid",
		"setresuid32",
		"setreuid",
		"setrlimit",
		"setsid",
		"setsockopt",
		"settimeofday",
		"setuid",
		"setuid32",
		"setxattr",
		"set_robust_list",
		"set_thread_area",
		"set_tid_address",
		"sgetmask",
		"shmat",
		"shmctl",
		"shmdt",
		"shutdown",
		"sigaltstack",
		"signal",
		"signalfd",
		"signalfd4",
		"sigpending",
		"sigprocmask",
		"socket",
		"socketpair",
		"splice",
		"ssetmask",
		"stat",
		"stat64",
		"statfs",
		"statfs64",
		"stime",
		"swapoff",
		"swapon",
		"symlink",
		"symlinkat",
		"sync",
		"syncfs",
		"sysfs",
		"sysinfo",
		"syslog",
		"tee",
		"tgkill",
		"timerfd_create",
		"timerfd_gettime",
		"timerfd_settime",
		"timer_create",
		"timer_delete",
		"timer_getoverrun",
		"timer_gettime",
		"timer_settime",
		"times",
		"tkill",
		"truncate",
		"ugetrlimit",
		"umask",
		"umount",
		"umount2",
		"uname",
		"unlink",
		"unlinkat",
		"unshare",
		"uselib",
		"ustat",
		"utime",
		"utimensat",
		"utimes",
		"vfork",
		"vhangup",
		"vmsplice",
		"wait4",
		"waitid",
		"waitpid",
		"write",
		"writev",
	}
)

const (
	apparmorRuleTemplate = `
  - rule: File Integrity Management
    desc: File Integrity Management
    condition: >
      (open_write or open_read) and (container.id != host) %s
`
	apparmorRuleOutput = `
    output: >
      APPARMOR data (container.name=%container.name container.id=%container.id evt.is_open_write=%evt.is_open_write evt.is_open_read=%evt.is_open_read evt.type=%evt.type evt.args=%evt.args fd.name=%fd.name syscall.type=%syscall.type)
    priority:
      WARNING
    tags: [apparmor]	
`
	seccompRuleTemplate = `
  - rule: Seccomp
    desc: Seccomp
    condition: >
      (container.id != host) %s
`
	seccompRuleOutput = `
    output: >
      SECCOMP data (container.name=%container.name container.id=%container.id evt.type=%evt.type evt.args=%evt.args fd.name=%fd.name syscall.type=%syscall.type)
    priority:
      WARNING
    tags: [seccomp]
`
	commandWhitelistRuleTemplate = `
  - rule: Command whitelist
    desc: Command whitelist
    condition: >
      (evt.type = execve) and (container.id != host) %s
`
	commandWhitelistRuleOutput = `
    output: >
      CW data (container.name=%container.name container.id=%container.id proc.exepath=%proc.exepath proc.exe=%proc.exe proc.cwd=%proc.cwd proc.exeline=%proc.exeline evt.type=%evt.type evt.args=%evt.args fd.name=%fd.name proc.exeline=%proc.exeline syscall.type=%syscall.type)
    priority:
      WARNING
    tags: [command-whitelist]	
`
)

type FalcoService struct {
	db        *rdbtools.GormWrapper
	k8sClient *kubernetes.Clientset
}

var (
	instance *FalcoService
	once     sync.Once
)

func Init(
	db *rdbtools.GormWrapper,
	k8sClient *kubernetes.Clientset,
) error {
	once.Do(func() {
		instance = &FalcoService{
			db:        db,
			k8sClient: k8sClient,
		}
	})

	return nil
}

func Get() (*FalcoService, bool) {
	return instance, instance != nil
}

func (s *FalcoService) RestartFalco(ctx context.Context) error {
	falcoLabel := os.Getenv("HOLMES_LABEL")
	if falcoLabel == "" {
		return fmt.Errorf("HOLMES_LABEL environment variable not set")
	}
	namespace := os.Getenv("MY_POD_NAMESPACE")
	if namespace == "" {
		return fmt.Errorf("MY_POD_NAMESPACE environment variable not set")
	}
	labelSelector := metav1.LabelSelector{
		MatchLabels: map[string]string{
			"app": falcoLabel,
		},
	}
	listOpts := metav1.ListOptions{LabelSelector: labels.Set(labelSelector.MatchLabels).String()}

	podList, err := s.k8sClient.CoreV1().Pods(namespace).List(ctx, listOpts)
	if err != nil {
		return err
	}
	for _, pod := range podList.Items {
		err = s.k8sClient.CoreV1().Pods(namespace).Delete(ctx, pod.Name, metav1.DeleteOptions{})
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *FalcoService) AddContentFilterToFalcoRulesConfigMap(ctx context.Context, secProfileIntermediateData []model.SecProfileIntermediate) error {
	myNamespace := os.Getenv("MY_POD_NAMESPACE")
	falcoConfigMap := os.Getenv("HOLMES_CONFIGMAP")
	configMap, err := s.k8sClient.CoreV1().ConfigMaps(myNamespace).Get(ctx, falcoConfigMap, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if configMap.Data == nil {
		configMap.Data = make(map[string]string)
	}
	filters := make(map[model.SecurityKind]string)
	vals := make(map[model.SecurityKind]string)
	apparmorFilterParts := make([]string, 0)
	seccompFilterParts := make([]string, 0)
	commandWhitelistFilterParts := make([]string, 0)
	for _, profile := range secProfileIntermediateData {
		dbctx, dbcancel := context.WithTimeout(ctx, 10*time.Second)
		defer dbcancel()
		var p model.SecurityPolicy

		result := s.db.Get().WithContext(dbctx).Preload(clause.Associations).First(&p, profile.PolicyID)
		if result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				logging.GetLogger().Error().Err(result.Error).Msg("Policy with given ID doesn't exist in database")
				continue
			}
			logging.GetLogger().Error().Err(result.Error).Msg("Error getting policy from db database")
			continue
		}
		for _, resource := range p.Resources {
			whitelist := make([]string, 0)
			if profile.SecProfileEnvelope.Kind == model.SecurityKindApparmor {
				for _, k := range profile.SecProfileEnvelope.ApparmorProfileData {
					whitelist = append(whitelist, k.File)
				}
				apparmorFilterParts = append(apparmorFilterParts, s.createResourceFilter(string(resource.Kind), resource.Name, resource.Namespace, profile.SecProfileEnvelope.Kind, whitelist))
			} else if profile.SecProfileEnvelope.Kind == model.SecurityKindCommandWhitelist {
				for _, cmd := range profile.SecProfileEnvelope.CommandWhitelistProfileData {
					whitelist = append(whitelist, fmt.Sprintf("%s PWD=%s", cmd.Command, cmd.WorkingDirectory))
				}
				commandWhitelistFilterParts = append(commandWhitelistFilterParts, s.createResourceFilter(string(resource.Kind), resource.Name, resource.Namespace, profile.SecProfileEnvelope.Kind, whitelist))
			} else if profile.SecProfileEnvelope.Kind == model.SecurityKindSeccomp {
				for _, v := range profile.SecProfileEnvelope.SeccompProfileData {
					whitelist = append(whitelist, v.Syscall)
				}
				seccompFilterParts = append(seccompFilterParts, s.createResourceFilter(string(resource.Kind), resource.Name, resource.Namespace, profile.SecProfileEnvelope.Kind, whitelist))
			} else {
				logging.GetLogger().Error().Str("kind", string(profile.SecProfileEnvelope.Kind)).Msg("Unknown security profile kind")
				return fmt.Errorf("Unknown security profile kind: %s", string(profile.SecProfileEnvelope.Kind))
			}
		}

	}
	filters[model.SecurityKindApparmor] = strings.Join(apparmorFilterParts, " or ")
	filters[model.SecurityKindCommandWhitelist] = strings.Join(commandWhitelistFilterParts, " or ")
	filters[model.SecurityKindSeccomp] = strings.Join(seccompFilterParts, " or ")
	needRestart := false
	for _, kind := range []model.SecurityKind{
		model.SecurityKindApparmor,
		model.SecurityKindCommandWhitelist,
		model.SecurityKindSeccomp,
	} {
		filter := filters[kind]
		if filter != "" {
			filter = " and (" + filter + ")"
			var newVal = ""
			var oldVal = ""
			if kind == model.SecurityKindApparmor {
				if v, ok := configMap.Data[string(model.SecurityKindApparmor)]; ok {
					oldVal = v
				}
				newVal = fmt.Sprintf(apparmorRuleTemplate, filter) + "\n" + apparmorRuleOutput
			} else if kind == model.SecurityKindCommandWhitelist {
				if v, ok := configMap.Data[string(model.SecurityKindCommandWhitelist)]; ok {
					oldVal = v
				}
				newVal = fmt.Sprintf(commandWhitelistRuleTemplate, filter) + "\n" + commandWhitelistRuleOutput
			} else if kind == model.SecurityKindSeccomp {
				if v, ok := configMap.Data[string(model.SecurityKindSeccomp)]; ok {
					oldVal = v
				}
				newVal = fmt.Sprintf(seccompRuleTemplate, filter) + "\n" + seccompRuleOutput
			} else {
				logging.GetLogger().Error().Str("kind", string(kind)).Msg("Unsupported security profile kind")
				return fmt.Errorf("Unsupported profile kind %s", kind)
			}
			vals[kind] = newVal
			if oldVal != newVal {
				needRestart = true
			}
		} else {
			var oldVal = ""
			if kind == model.SecurityKindApparmor {
				oldVal = configMap.Data[string(model.SecurityKindApparmor)]
			} else if kind == model.SecurityKindCommandWhitelist {
				oldVal = configMap.Data[string(model.SecurityKindCommandWhitelist)]
			} else if kind == model.SecurityKindSeccomp {
				oldVal = configMap.Data[string(model.SecurityKindSeccomp)]
			} else {
				logging.GetLogger().Error().Str("kind", string(kind)).Msg("Unsupported security profile kind")
				return fmt.Errorf("Unsupported profile kind %s", kind)
			}
			if oldVal != "" {
				needRestart = true
				vals[kind] = ""
			}
		}
	}
	if !needRestart {
		return nil
	}
	err = s.updateFalcoRulesConfigMap(ctx, configMap, myNamespace, vals)

	return err
}

func (s *FalcoService) createResourceFilter(resourceKind string, resourceName string, resourceNamespace string, kind model.SecurityKind, whitelist []string) string {
	filter := fmt.Sprintf("((k8s.pod.name startswith %s) and (k8s.ns.name = %s)", resourceName, resourceNamespace)
	if kind == model.SecurityKindApparmor {
		apparmorFilterList := ""
		for _, a := range whitelist {
			filename := strings.Split(a, " ")[0]
			if apparmorFilterList == "" {
				apparmorFilterList = fmt.Sprintf("fd.name != %s", filename)
			} else {
				apparmorFilterList = apparmorFilterList + fmt.Sprintf(" and fd.name != %s", filename)
			}
		}
		apparmorFilter := ""
		if apparmorFilterList != "" {
			apparmorFilter = fmt.Sprintf(" and (%s)", apparmorFilterList)
		}
		filter = filter + apparmorFilter
	} else if kind == model.SecurityKindCommandWhitelist {
		commandWhitelistFilterList := ""
		// TODO: Fix according to how it is being processed in eventProcessor
		// for _, a := range whitelist {
		// cSplit := strings.Split(a, " PWD=")
		// executableWithArgs := cSplit[0]
		// executableWithArgsSplit := strings.Split(executableWithArgs, " ")
		// executable := executableWithArgsSplit[0]
		// exeline := strings.Split("/", executable)[len(strings.Split("/", executable))-1] + strings.Join(executableWithArgsSplit[1:], " ")
		// cwd := cSplit[1]
		//
		// if commandWhitelistFilterList == "" {
		// 	commandWhitelistFilterList = fmt.Sprintf("(proc.cwd != %s and proc.exepath != %s and proc.exeline != %s)", cwd, executable, exeline)
		// } else {
		// 	commandWhitelistFilterList = commandWhitelistFilterList + fmt.Sprintf(" and (proc.cwd != %s and proc.exepath != %s and proc.exeline != %s)", cwd, executable, exeline)
		// }
		// }
		commandWhitelistFilter := ""
		if commandWhitelistFilterList != "" {
			commandWhitelistFilter = fmt.Sprintf(" and (%s)", commandWhitelistFilterList)
		}
		filter = filter + commandWhitelistFilter
	} else if kind == model.SecurityKindSeccomp {
		seccompFilterList := ""
		for _, s := range SeccompEventsToWatch {
			if !util.ContainsString(whitelist, s) {
				if seccompFilterList == "" {
					seccompFilterList = fmt.Sprintf("syscall.type = %s", s)
				} else {
					seccompFilterList = seccompFilterList + fmt.Sprintf(" or syscall.type = %s", s)
				}
			}
		}
		seccompFilter := ""
		if seccompFilterList != "" {
			seccompFilter = fmt.Sprintf(" and (%s)", seccompFilterList)
		}
		filter = filter + seccompFilter
	} else {
		logging.GetLogger().Error().Str("kind", string(kind)).Msg("Unsupported security profile kind")
		return ""
	}
	return filter + ")"
}

func (s *FalcoService) updateFalcoRulesConfigMap(ctx context.Context, configmap *v1.ConfigMap, namespace string, vals map[model.SecurityKind]string) error {
	for k, v := range vals {
		if v != "" {
			configmap.Data[string(k)] = v
		} else {
			delete(configmap.Data, string(k))
		}
	}
	_, err := s.k8sClient.CoreV1().ConfigMaps(namespace).Update(ctx, configmap, metav1.UpdateOptions{})
	return err
}
