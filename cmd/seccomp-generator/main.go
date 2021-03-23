package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"sync"

	log "github.com/sirupsen/logrus"

	seccompExtensionV1 "gitlab.com/piccolo_su/vegeta/pkg/api/types/v1alpha"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
)

var mutex = &sync.Mutex{}

type SeccompGenerator struct {
	restClient *rest.RESTClient
}

type SyscallWhitelist struct {
	PodName  string   `json:"pod"`
	Syscalls []string `json:"syscalls"`
	UUID     string   `json:"uuid"`
	Mode     string   `json:"mode"`
}

func (sg *SeccompGenerator) addSeccompProfile(w http.ResponseWriter, r *http.Request) {
	mutex.Lock()
	defer mutex.Unlock()
	myNamespace := os.Getenv("MY_POD_NAMESPACE")

	if r.URL.Path != "/" {
		http.Error(w, "404 not found.", http.StatusNotFound)
		return
	}
	switch r.Method {
	case "POST":
		b, err := ioutil.ReadAll(r.Body)
		defer r.Body.Close()
		if err != nil {
			log.Errorf("Failed to read body: %w", err)
			http.Error(w, err.Error(), 500)
			return
		}

		var s SyscallWhitelist
		err = json.Unmarshal(b, &s)
		if err != nil {
			log.Errorf("Failed to unmarshal body: %w", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		architectures := []*seccompExtensionV1.Arch{}
		arch1 := seccompExtensionV1.Arch("SCMP_ARCH_X86_64")
		architectures = append(architectures, &arch1)
		arch2 := seccompExtensionV1.Arch("SCMP_ARCH_X86")
		architectures = append(architectures, &arch2)
		arch3 := seccompExtensionV1.Arch("SCMP_ARCH_X32")
		architectures = append(architectures, &arch3)

		syscalls := []*seccompExtensionV1.Syscall{}

		syscallList := []string{
			"accept",
			"accept4",
			"access",
			"arch_prctl",
			"bind",
			"brk",
			"capget",
			"capset",
			"chdir",
			"clock_gettime",
			"clone",
			"close",
			"connect",
			"dup2",
			"epoll_ctl",
			"epoll_pwait",
			"epoll_wait",
			"exec",
			"execve",
			"exit",
			"exit_group",
			"fcntl",
			"fcntl64",
			"fsetattrx",
			"fstat",
			"fstat64",
			"fstatat64",
			"fstatfs",
			"ftruncate64",
			"futex",
			"getdents",
			"getdents64",
			"getegid",
			"geteuid",
			"getgid",
			"getpgid",
			"getpgrp",
			"getsid",
			"getitimer",
			"getcwd",
			"getgroups",
			"getpid",
			"getppid",
			"getsockopt",
			"gettid",
			"getuid",
			"ioctl",
			"link",
			"linkat",
			"listen",
			"listxattr",
			"llistxattr",
			"lseek",
			"lstat64",
			"madvise",
			"mmap",
			"mount",
			"mprotect",
			"munmap",
			"nanosleep",
			"newfstatat",
			"open",
			"openat",
			"pciconfig_iobase",
			"pciconfig_read",
			"pciconfig_write",
			"poll",
			"ppoll",
			"prctl",
			"pread64",
			"pselect6",
			"pwrite",
			"pwrite64",
			"read",
			"readlink",
			"recvfrom",
			"recvmsg",
			"recvmmsg",
			"rt_sigaction",
			"rt_sigprocmask",
			"rt_sigreturn",
			"sched_getattr",
			"sched_setattr",
			"sched_yield",
			"seccomp",
			"sendfile",
			"sendfile64",
			"sendmsg",
			"sendmmsg",
			"sendto",
			"setitimer",
			"setgid",
			"setgroups",
			"set_robust_list",
			"setsockopt",
			"setuid",
			"sigaltstack",
			"socket",
			"socketpair",
			"stat",
			"statfs",
			"sysinfo",
			"timerfd_gettime",
			"timer_gettime",
			"times",
			"tkill",
			"truncate",
			"truncate64",
			"umask",
			"uname",
			"unlink",
			"unlinkat",
			"utimensat",
			"ustat",
			"utimensat",
			"utimes",
			"wait4",
			"waitid",
			"write",
			"writev",
			"vfork",
		}

		for _, syscall := range s.Syscalls {
			log.Infof("Adding %s to %s", syscall, s.PodName)
			syscallList = AppendIfMissing(syscallList, syscall)
		}

		syscallWhitelist := seccompExtensionV1.Syscall{
			Action: "SCMP_ACT_ALLOW",
			Names:  syscallList,
		}

		syscalls = append(syscalls, &syscallWhitelist)

		oldSeccompProfile := seccompExtensionV1.SeccompProfile{}

		err = sg.restClient.
			Get().
			Resource("seccompprofiles").
			Name(s.PodName).
			Namespace(myNamespace).
			Do().
			Into(&oldSeccompProfile)
		if err != nil {
			// TODO: parse *errors.StatusError
			// seccompprofiles.security-profiles-operator.x-k8s.io "85da72c140fb88180bcbb91a7dd8318fba3630c0c62169202887390b1ba36f8c" not found
			log.Infof("Seccomp profile for %s error: %w", s.PodName, err)
		} else {
			log.Infof("Found existing seccomp profile for %s", s.PodName)
			for k, v := range oldSeccompProfile.Labels {
				if k == "generation.uuid" {
					if v == s.UUID {
						log.Infof("Existing seccomp profile %s generated in current seccomp-generation run. Merging allowed syscalls", s.PodName)
						oldSeccompProfileSyscalls := oldSeccompProfile.Spec.Syscalls
						if len(oldSeccompProfileSyscalls) > 0 {
							for _, syscall := range oldSeccompProfileSyscalls[0].Names {
								syscallList = AppendIfMissing(syscallList, syscall)
							}
						}
					} else {
						log.Infof("Existing seccomp profile %s generated in previous seccomp-generation run", s.PodName)
					}
				}
			}
			err = sg.restClient.
				Delete().
				Resource("seccompprofiles").
				Name(oldSeccompProfile.Name).
				Namespace(oldSeccompProfile.Namespace).
				Do().
				Error()
			if err != nil {
				log.Errorf("Failed to remove seccomp profile: %w", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}

		var mode string
		if s.Mode == "PREVENT" {
			mode = "SCMP_ACT_ERRNO"
		} else {
			mode = "SCMP_ACT_LOG"
		}

		newLabels := make(map[string]string)
		newLabels["generation.uuid"] = s.UUID

		newSeccompProfile := seccompExtensionV1.SeccompProfile{
			TypeMeta: v1.TypeMeta{
				APIVersion: "security-profiles-operator.x-k8s.io/v1alpha1",
				Kind:       "SeccompProfile",
			},
			ObjectMeta: v1.ObjectMeta{
				Name:      s.PodName,
				Namespace: myNamespace,
				Labels:    newLabels,
			},
			Spec: seccompExtensionV1.SeccompProfileSpec{
				TargetWorkload: "tensorsec-profiles",
				DefaultAction:  mode,
				Architectures:  architectures,
				Syscalls:       syscalls,
			},
		}

		log.Infof("Seccomp profile %s prepared", s.PodName)
		body, err := json.Marshal(newSeccompProfile)

		for i := 0; i < 10; i++ {
			_, err = sg.restClient.
				Post().
				AbsPath(fmt.Sprintf("/apis/security-profiles-operator.x-k8s.io/v1alpha1/namespaces/%s/seccompprofiles", myNamespace)).
				Body(body).
				DoRaw()

			if err != nil {
				log.Errorf("Try %d : Seccomprofile k8s api err: %v", i, err)
			} else {
				log.Infof("Seccomp profile %s generated", s.PodName)
				return
			}
		}
		if err != nil {
			log.Errorf("Seccomp profile %s not generated", s.PodName)
		} else {
			log.Infof("Seccomp profile %s generated", s.PodName)
		}
	default:
		http.Error(w, "other than POST not supprted", http.StatusNotFound)
	}
}

func AppendIfMissing(slice []string, i string) []string {
	for _, ele := range slice {
		if ele == i {
			return slice
		}
	}
	return append(slice, i)
}

func main() {
	var config *rest.Config
	config, err := rest.InClusterConfig()
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Failed to get in-cluster config")
	}

	seccompExtensionV1.AddToScheme(scheme.Scheme)

	crdConfig := *config
	crdConfig.ContentConfig.GroupVersion = &seccompExtensionV1.GroupVersion
	crdConfig.APIPath = "/apis"
	crdConfig.NegotiatedSerializer = serializer.NewCodecFactory(scheme.Scheme)
	crdConfig.UserAgent = rest.DefaultKubernetesUserAgent()

	restClient, err := rest.UnversionedRESTClientFor(&crdConfig)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Failed to initialize rest client")
	}

	sg := SeccompGenerator{
		restClient: restClient,
	}

	http.HandleFunc("/", sg.addSeccompProfile)

	fmt.Printf("Server started\n")
	if err := http.ListenAndServe(":6969", nil); err != nil {
		log.Fatal(err)
	}
}
