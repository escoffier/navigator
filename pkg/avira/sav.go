package avira

import (
	"fmt"
	"os/exec"
	"runtime/debug"
	"sync"
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
	DefaultSavApiLogFile    = "/tmp/sav-server.log"
)

type SavServer struct {
	listenPort int64
	notifyChan chan struct{} // 用于外部通知是否停止server
	endChan    chan struct{} // 通知外部server停止了。
}

type Option func(s *SavServer)

func WithListenPort(port int64) Option {
	return func(s *SavServer) {
		s.listenPort = port
	}
}

func (s *SavServer) GetListenPort() int64 {
	return s.listenPort
}

func (s *SavServer) generateDaemonCmd() string {
	cmdStr := fmt.Sprintf("%s -N --tcp=%d -C %s --log-file=%s", savApiBin, s.listenPort, savApiConf, DefaultSavApiLogFile)
	return cmdStr
}

func (s *SavServer) IsSavServerRunning() (bool, error) {
	processes, err := process.Processes()
	if err != nil {
		return false, err
	}
	for _, p := range processes {
		n, err := p.Name()
		if err != nil {
			logging.Get().Err(err).Msg("failed to get process name")
			continue
		}
		if n == savApiBinBase {
			return true, nil
		}
	}
	return false, nil
}

func (s *SavServer) KillSavServerProcess() error {
	processes, err := process.Processes()
	if err != nil {
		return err
	}
	for _, p := range processes {
		n, err := p.Name()
		if err != nil {
			logging.Get().Err(err).Msg("failed to get process name")
			continue
		}
		if n == savApiBinBase {
			return p.Kill()
		}
	}
	return fmt.Errorf("process not found")
}

func (s *SavServer) NotifyStop() {
	s.notifyChan <- struct{}{}
}

func (s *SavServer) EndChan() chan struct{} {
	return s.endChan
}

func (s *SavServer) Run() {
	daemonCmdStr := s.generateDaemonCmd()

	// 启动server
	shouldStop := false
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("panic: %v.stack:%s", r, debug.Stack())
			}
		}()
		defer wg.Done()
		for {
			cmd := exec.Command("sh", "-c", daemonCmdStr)
			err := cmd.Start()
			if err != nil {
				logging.Get().Err(err).Msg("failed to start sav daemon")
				time.Sleep(10 * time.Second)
				continue
			}
			logging.Get().Info().Msg("start sav daemon ok")

			err = cmd.Wait()
			logging.Get().Debug().Bool("stopFlag", shouldStop).Msgf("sav daemon exit,check stop flag.%v", err)
			if shouldStop {
				logging.Get().Info().Msg("receive stop signal,server quit and not restart")
				break
			}

			// some exception,try restart
			logging.Get().Err(err).Msg("sav daemon exit,try restart")
		}
	}()

	// 等待stop 信号
	wg.Add(1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("panic: %v.stack:%s", r, debug.Stack())
			}
		}()
		defer wg.Done()

		// wait stop signal
		signal := <-s.notifyChan
		shouldStop = true
		logging.Get().Info().Msgf("receive stop signal,kill sav server.%v", signal)

		// kill server process
		err := s.KillSavServerProcess()
		if err != nil {
			logging.Get().Err(err).Msg("failed to kill sav server")
			return
		}
		// todo: check if killed ok
		logging.Get().Info().Msg("success to kill sav server")
	}()

	wg.Wait()
	s.endChan <- struct{}{}
	logging.Get().Info().Msg("sav server exit")
}

func NewSavServer(opts ...Option) (*SavServer, error) {
	s := &SavServer{
		listenPort: DefaultSavApiListenAddr,
		notifyChan: make(chan struct{}, 1),
		endChan:    make(chan struct{}, 1),
	}
	for _, option := range opts {
		option(s)
	}
	return s, nil
}
