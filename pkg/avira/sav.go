package avira

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/process"
	"gitlab.com/security-rd/go-pkg/logging"
)

const (
	savApiConf              = "/etc/savapi/savapi.conf"
	savApiBin               = "/usr/local/savapi-sdk-linux64/bin/savapi"
	savApiBinBase           = "savapi"
	DefaultSavApiPath       = "/usr/local/savapi-sdk-linux64"
	DefaultSavApiListenAddr = 9180
	DefaultSavApiLogFile    = "/tmp/avira-server.log"
)

type SavServer struct {
	ListenPort int64
	PID        int // 进程执行的 PID
	ShouldStop bool
}

type Option func(s *SavServer)

func WithListenPort(port int64) Option {
	return func(s *SavServer) {
		s.ListenPort = port
	}
}

func (s *SavServer) generateDaemonArgs() []string {
	// cmdStr := fmt.Sprintf("%s -N --tcp=%d -C %s --log-file=%s", savApiBin, s.ListenPort, savApiConf, DefaultSavApiLogFile)
	cmdStr := fmt.Sprintf("-N --tcp=%d -C %s --log-file=%s", s.ListenPort, savApiConf, DefaultSavApiLogFile)
	return strings.Split(cmdStr, " ")
}

func (s *SavServer) IsServerRunning() (bool, error) {
	processes, err := process.Processes()
	if err != nil {
		return false, err
	}
	for _, p := range processes {
		if p.Pid == int32(s.PID) {
			return true, nil
		}
	}
	return false, nil
}

func (s *SavServer) KillServer() error {
	s.ShouldStop = true

	running, err := s.IsServerRunning()
	if err != nil {
		return err
	}
	if !running {
		logging.Get().Info().Msg("avira server not running")
		return nil
	}

	processes, err := process.Processes()
	if err != nil {
		logging.Get().Info().Int("PID", s.PID).Msg("not find processes")
		return err
	}
	find := false
	for _, p := range processes {
		if p.Pid == int32(s.PID) {
			find = true
			logging.Get().Info().Int("PID", s.PID).Msg("find pid and kill")
			if err := p.Kill(); err != nil {
				return err
			}
			break
		}
	}
	if !find {
		return fmt.Errorf("kill avira server but not fond process")
	}
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	cnt := 0
	for cnt < 10 {
		<-ticker.C
		if run, err := s.IsServerRunning(); err == nil && run {
			break
		}
		logging.Get().Info().Int("PID", s.PID).Msg("avira server not killed")
		cnt++
	}

	s.PID = 0
	return nil
}

func (s *SavServer) StartServer() {
	ticker := time.NewTicker(time.Second * 30)
	defer ticker.Stop()

	for {
		<-ticker.C

		if s.ShouldStop {
			break
		}

		if s.PID > 0 {
			running, err := s.IsServerRunning()
			if err == nil && running {
				logging.Get().Debug().Int("PID", s.PID).Msg("avira server is running")
				continue
			}
		}
		if s.PID > 0 {
			_ = s.KillServer()
		}
		// 然后重新启动
		// cmd := exec.Command("sh", "-c", daemonCmdStr)
		cmd := exec.Command(savApiBin, s.generateDaemonArgs()...)
		err := cmd.Start()
		logging.Get().Info().Strs("cmd", cmd.Args).Msg("start avira service")
		if err != nil {
			logging.Get().Err(err).Msg("failed to start avira daemon")
			continue
		}

		s.PID = cmd.Process.Pid

		logging.Get().Info().Int("PID", cmd.Process.Pid).Msg("start avira daemon ok")
		if err = cmd.Wait(); err != nil {
			logging.Get().Err(err).Int("PID", cmd.Process.Pid).Msg("start avira daemon ok,but cmd not wait")
		}
		wait, err := cmd.Process.Wait()
		if err != nil {
			logging.Get().Err(err).Int("PID", cmd.Process.Pid).Msg("start avira daemon ok,but Process not wait")
			continue
		}
		if wait.Exited() {
			logging.Get().Info().Int("PrePID", cmd.Process.Pid).Msg("avira daemon Exited")
			s.PID = 0
			continue
		}
	}
}

func NewSavServer(opts ...Option) *SavServer {
	s := &SavServer{
		ListenPort: DefaultSavApiListenAddr,
		PID:        0,
	}
	for _, option := range opts {
		option(s)
	}
	return s
}
