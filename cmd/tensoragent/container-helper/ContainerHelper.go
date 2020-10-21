package containerhelper

import (
	"fmt"

	ps "gitlab.com/piccolo_su/vegeta/cmd/tensoragent/go-ps"
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

func (cu ContainerUtil) GetContainerId(pid int) (int, error) {
	fmt.Println("Checking container cache")
	cid, err := cu.pidCache.Get(pid)

	if err == nil {
		return cid, nil
	}

	p, err := ps.FindProcess(pid)

	if err != nil || p == nil {
		return -1, err
	}

	not_init := true
	for not_init {
		if p.Executable() == "containerd-shim" {
			cid = p.Pid()
			cu.pidCache.Set(pid, cid)
			return cid, nil
		}

		p, err = ps.FindProcess(p.PPid())

		if p == nil || err != nil {
			return -1, nil
		}

		if 1 == p.Pid() {
			not_init = false
		}
	}

	cu.pidCache.Set(pid, 0)
	return 0, nil
}
