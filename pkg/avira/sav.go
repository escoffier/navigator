package avira

import (
	"fmt"
	"gitlab.com/security-rd/go-pkg/logging"
	"os/exec"
	"time"
)

const (
	savApiConf              = "/etc/savapi/savapi.conf"
	savApiBin               = "/usr/local/savapi-sdk-linux64/bin/savapi"
	DefaultSavApiListenAddr = 9180
)

type SavServer struct {
}

func (s *SavServer) generateDaemonCmd() string {
	cmdStr := fmt.Sprintf("%s -N --tcp=%d -C %s", savApiBin, DefaultSavApiListenAddr, savApiConf)
	return cmdStr
}

func (s *SavServer) Run() {
	daemonCmdStr := s.generateDaemonCmd()
	cmd := exec.Command("sh", "-c", daemonCmdStr)

	for {
		logging.Get().Info().Msg("start sav server")
		err := cmd.Run()
		logging.Get().Err(err).Msg("sav daemon exit,try restart")
		time.Sleep(10 * time.Second)
	}
}

func NewSavServer() (*SavServer, error) {
	s := &SavServer{}
	return s, nil
}
