package containerhelper

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	ps "gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/utils/go-ps"
)

type ContainerUtil struct {
	pidCache PidCache
}

// NewContainer instantiates a default password store
func NewContainerUtil() ContainerUtil {
	return ContainerUtil{
		NewPidCache(),
	}
}

func (cu ContainerUtil) Init() error {
	return cu.pidCache.Init()
}

func (cu ContainerUtil) GetContainerPid(pid int) (int, error) {
	log.Info("Checking container cache")
	dockerPID, err := cu.pidCache.Get(pid)

	if err == nil {
		log.Infof("Found docker pid %d in cache for %d process", dockerPID, pid)
		return dockerPID, nil
	}

	p, err := ps.FindProcess(pid)
	if err != nil || p == nil {
		log.Error(fmt.Sprintf("Could not find process information for %d. Probably vanished", pid), err)
		return 0, err
	}

	notInit := true
	for notInit {
		log.Infof("Process %d executable: %s", p.Pid(), p.Executable())
		if p.Executable() == "containerd-shim" {
			dockerPID = p.Pid()
			log.Infof("Current checked PID %d is containerd-shim. Persist it as docker pid for %d\n", dockerPID, pid)
			cu.pidCache.Set(pid, dockerPID)
			return dockerPID, nil
		}
		// TODO: need to have larger buffer for executable...
		if p.Executable() == "docker-containerd-shim" || p.Executable() == "docker-containe" {
			dockerPID = p.Pid()
			log.Infof("Current checked PID %d is docker-containerd-shim. Persist it as docker pid for %d\n", dockerPID, pid)
			cu.pidCache.Set(pid, dockerPID)
			return dockerPID, nil
		}

		p, err = ps.FindProcess(p.PPid())
		if p == nil || err != nil {
			log.Error(fmt.Sprintf("Could not find process information for %d parent. Probably vanished or not existing", pid), err)
			return 0, nil
		}
		log.Infof("Searching for parent process information %d of %d\n", p.PPid(), p.Pid())

		if 1 == p.Pid() {
			log.Info("Reached init process ID")
			notInit = false
		}
	}

	log.Info("Reached init process ID. Persisting")
	cu.pidCache.Set(pid, 1)
	return 1, nil
}
