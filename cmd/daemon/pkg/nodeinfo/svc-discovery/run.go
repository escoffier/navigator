package svcdiscovery

import (
	"context"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/security-rd/go-pkg/logging"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
)

var childrenPathFormat = "/proc/%s/task/%s/children"
var cmdPathFormat = "/proc/%s/cmdline"
var gPrefixPath = "/host"

// 对应容器里面执行命令
var runCmd func(ctx context.Context, containerId string, cmd []string) (string, error)

type DiscoveryHandler struct {
	svcHandler       []ISvcDiscovery
	frameworkHandler []IFrameworkDiscovery
	pathPrefix       string
}

func NewDiscoveryHandler(hostPrefix string, remoteRunFunc func(ctx context.Context, containerId string, cmd []string) (string, error)) *DiscoveryHandler {
	runCmd = remoteRunFunc
	if runCmd == nil {
		runCmd = func(ctx context.Context, containerId string, cmd []string) (string, error) {
			return "", nil
		}
	}
	return &DiscoveryHandler{
		svcHandler: []ISvcDiscovery{NewTomcatSvc(), NewApacheSvc(), NewNginxSvc(), NewWeblogicSvc(), NewWebSphereSvc(), NewWildflySvc(), NewOpenRestySvc(),
			NewMysqlSvc(), NewPostgreSQLSvc(), NewMogoDbSvc(), NewRedisSvc(), NewGrafanaSvc(), NewRsyslogSvc()},
		frameworkHandler: []IFrameworkDiscovery{NewJava(), NewPython(), NewPhp(), NewNet(), NewRuby(), NewNodejs()},
		pathPrefix:       hostPrefix,
	}
}

func (ds *DiscoveryHandler) Discovery(containerId, pid string, cwd string) ([]*assets.ContainerFrameworkInfo, []*assets.ContainerSvcInfo, error) {
	defer func() {
		if r := recover(); r != nil {
			logging.Get().Error().Msgf("Discovery failed. containerId:%s, %v , stack:%s", containerId, r, debug.Stack())
		}
	}()

	if len(pid) == 0 {
		return nil, nil, fmt.Errorf("pid is empty")
	}
	var cmdList []*cmdItem
	ds.findChildrenCmd(pid, &cmdList)

	if len(cmdList) == 0 {
		logging.Get().Error().Msgf("get  cmdList is empty ,pid:%s", pid)
		return nil, nil, nil
	}
	logging.Get().Debug().Msgf("Discovery  containerId:%s,pid:%s", containerId, pid)

	var frameworkList []*assets.ContainerFrameworkInfo
	var svcList []*assets.ContainerSvcInfo

	for _, frameworkDiscovery := range ds.frameworkHandler {
		if frameworkDiscovery == nil {
			continue
		}
		framework := frameworkDiscovery.FrameworkDiscovery(containerId, cmdList)
		if framework != nil {
			if framework.FrameworkName == "" && framework.FrameworkVersion != "" {
				// todo
				logging.Get().Warn().Msgf("find err, containerId:%s,framework:%v", framework)
				framework.FrameworkVersion = ""
			}
			frameworkList = append(frameworkList, framework)
		}
	}

	for _, handler := range ds.svcHandler {
		if handler == nil {
			continue
		}
		svc := handler.SvcDiscovery(cmdList, cwd, containerId)
		if svc != nil {
			svcList = append(svcList, svc)
		}
	}
	logging.Get().Debug().Msgf("Discovery containerId:%s result: pid:%s,frameworkCount:%d,svcCount:%d", containerId, pid, len(frameworkList), len(svcList))
	return frameworkList, svcList, nil
}

type cmdItem struct {
	pid    string
	cmdStr string
}

func (ds *DiscoveryHandler) findChildrenCmd(pid string, cmds *[]*cmdItem) {
	if len(pid) == 0 {
		return
	}
	cmdPath := fmt.Sprintf(ds.pathPrefix+cmdPathFormat, pid)
	fileBytes, err := os.ReadFile(cmdPath)
	if err != nil {
		logging.Get().Error().Msgf("handle "+cmdPath+" failed. ", err)
		return
	}
	item := &cmdItem{
		pid:    pid,
		cmdStr: strings.ReplaceAll(string(fileBytes), "\x00", " "),
	}
	*cmds = append(*cmds, item)
	childrenPath := fmt.Sprintf(ds.pathPrefix+childrenPathFormat, pid, pid)
	childrenBytes, err := os.ReadFile(childrenPath)
	if err != nil {
		logging.Get().Error().Msgf("error: handle "+childrenPath+" failed. ", err)
	} else {
		childrenList := strings.Split(strings.TrimSpace(string(childrenBytes)), " ")
		for _, children := range childrenList {
			ds.findChildrenCmd(children, cmds)
		}
	}

}

func getBinaryPathByPid(pid string) string {
	if pid == "" {
		return ""
	}
	exePath := fmt.Sprintf("%s/proc/%s/exe", gPrefixPath, pid)
	cmd := exec.Command("readlink", exePath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		logging.Get().Err(err).Msgf("getBinaryPathByPid failed. pid:%s,exePath:%s", pid, exePath)
	}
	return strings.TrimSpace(string(out))
}
