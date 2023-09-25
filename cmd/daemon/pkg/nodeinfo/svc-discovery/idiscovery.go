package svcdiscovery

import (
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"strings"
)

type ISvcDiscovery interface {
	SvcDiscovery(cmdList []*cmdItem, cwd string, containerId string) *assets.ContainerSvcInfo
}

type IFrameworkDiscovery interface {
	FrameworkDiscovery(containerId string, cmdList []*cmdItem) *assets.ContainerFrameworkInfo
}

func parseCmdBySpace(cmd string) (binary string, arg []string) {
	if len(cmd) == 0 {
		return "", nil
	}
	list := strings.Split(cmd, " ")
	if len(list) > 1 {
		return list[0], list[1:]
	}
	return list[0], nil
}

func parseCmdOnlyBinaryAndArgus(cmd string) (binary string, args string) {
	if len(cmd) == 0 {
		return "", ""
	}
	list := strings.SplitN(cmd, " ", 2)
	if len(list) == 2 {
		return list[0], list[1]
	}
	return list[0], ""
}
