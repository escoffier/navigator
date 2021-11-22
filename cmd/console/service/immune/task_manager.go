package immune

import (
	"context"
	"fmt"
	"runtime/debug"
	"strings"
	"time"

	json "github.com/json-iterator/go"
	"gitlab.com/piccolo_su/vegeta/pkg/dal"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gorm.io/gorm"
)

var (
	defaultSyscallWhitelist = []string{
		"accept",
		"accept4",
		"getppid",
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

type TaskManager struct {
	rdb *rdbtools.GormWrapper
}

func newTaskManager(rdb *rdbtools.GormWrapper) *TaskManager {
	tm := TaskManager{
		rdb: rdb,
	}
	tm.asyncLoop()

	return &tm
}

func (tm *TaskManager) setTaskDone(ctx context.Context, task *model.ImmuneTask, now time.Time) error {
	tctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	resources, err := dal.GetResources(tctx, tm.rdb.Get(), dal.ResourcesQuery().WithCustom("id", task.ResourceUUID), 0, 1)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("load resource for task err: %v. task: %v", err, task)
		return err
	}
	if len(resources) == 0 {
		logging.GetLogger().Err(err).Msgf("load resource for task no resource found. task: %v", err, task)
		return err
	}
	policy := &model.ImmunePolicy{
		Name:         fmt.Sprintf("%s/%s/%s %s Learned", resources[0].Namespace, resources[0].Kind, resources[0].Name, model.GetNameOfPolicyKind(task.PolicyKind)),
		ResourceUUID: task.ResourceUUID,
		Description:  "System Recommended Policy",
		Kind:         task.PolicyKind,
		ClusterKey:   resources[0].ClusterKey,
		Decision:     model.DecisionAlert,
		Status:       model.StatusDisable,
		Creator:      fmt.Sprintf("System-task-%d", task.ID),
		Updater:      fmt.Sprintf("System-task-%d", task.ID),
		UpdatedAt:    now,
		CreatedAt:    now,
	}

	txErr := tm.rdb.Get().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		policy, err := dal.CreateImmunePolicy(ctx, tx, policy)
		if err != nil {
			return err
		}

		fmt.Printf("p: %+v t: %+v r: %s\n", policy, task, resources[0].Name)
		var profiles []*model.ImmuneProfile
		if resources[0].PodTemplate != nil {
			for _, cont := range resources[0].PodTemplate.Containers {
				switch task.PolicyKind {
				case model.PolicyKindSyscalls:

					for _, syscall := range defaultSyscallWhitelist {
						profile := new(model.ImmuneProfile)
						profile.PolicyID = policy.ID
						profile.ContainerName = cont.Name
						profile.CreatedAt = now
						profile.Creator = fmt.Sprintf("System-task-%d", task.ID)
						profile.Value = []byte(syscall)

						profiles = append(profiles, profile)
					}
				case model.PolicyKindFileRW:
					if strings.Contains(resources[0].Name, "immune-test") && resources[0].Kind == "Deployment" {
						paths := []string{"/tdata/1.txt", "/tdata/1.txt", "/tdata/2.txt", "/tdata/2.txt"}
						rws := []string{"r", "w", "r", "w"}

						for i := 0; i < len(paths); i++ {
							profile := new(model.ImmuneProfile)
							profile.PolicyID = policy.ID
							profile.ContainerName = cont.Name
							profile.CreatedAt = now
							profile.Creator = fmt.Sprintf("System-task-%d", task.ID)
							var v model.FRWElement
							v.FilePath = paths[i]
							v.RW = rws[i]
							valBytes, err := json.Marshal(&v)
							if err != nil {
								logging.GetLogger().Err(err).Msgf("json marshal error. data: %+v", v)
								continue
							}
							profile.Value = valBytes
							profiles = append(profiles, profile)
						}
					}

				case model.PolicyKindCmdExec:
					if strings.Contains(resources[0].Name, "immune-test") && resources[0].Kind == "Deployment" {
						profile := new(model.ImmuneProfile)
						profile.PolicyID = policy.ID
						profile.ContainerName = cont.Name
						profile.CreatedAt = now
						profile.Creator = fmt.Sprintf("System-task-%d", task.ID)
						var v model.CmdExecElement
						v.CommandLine = "/bin/cat /tdata/1.txt"
						v.Env = ""
						valBytes, err := json.Marshal(&v)
						if err != nil {
							logging.GetLogger().Err(err).Msgf("json marshal error. data: %+v", v)
							continue
						}
						profile.Value = valBytes
						profiles = append(profiles, profile)
					}

				}
			}

		}

		for _, profile := range profiles {
			_, err := dal.CreateImmuneProfile(ctx, tx, profile)
			if err != nil {
				logging.GetLogger().Err(err).Msgf("create profile error. data: %+v", profile)
				return err
			}
		}

		return dal.SetImmuneTaskState(ctx, tx, task.ID, model.TStateLearned)
	})

	return txErr
}
func (tm *TaskManager) checkTaskState(ctx context.Context, now time.Time) {
	defer func() {
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("panic: %v. stack: %s", r, debug.Stack())
		}
	}()

	logging.GetLogger().Info().Msgf("check Tasks state starts")

	offset := 0
	for {
		tasks, err := dal.GetImmuneTasks(context.Background(), tm.rdb.Get(), dal.NewImmuneTasksQuery().WithState(model.TStateLearning), offset, 30)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("get tasks error")
			break
		}
		offset += len(tasks)
		if len(tasks) == 0 {
			break
		}
		for _, task := range tasks {
			if task.TerminatedAt.Before(now) {
				err := tm.setTaskDone(ctx, task, now)
				if err != nil {
					logging.GetLogger().Err(err).Msgf("Set task done error. task: %+v", task)
				} else {
					logging.GetLogger().Info().Msgf("Set task done. task: %+v", task)
				}
			}
		}

	}
	logging.GetLogger().Info().Msgf("check Tasks state ends")
}
func (tm *TaskManager) asyncLoop() {
	go func() {
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()

		for now := range ticker.C {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			tm.checkTaskState(ctx, now)
			cancel()
		}
	}()
}
