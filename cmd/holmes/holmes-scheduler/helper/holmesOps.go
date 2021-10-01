package holmeshelper

import (
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
)

const (
	securityProfilesRulesFolder = "/etc/holmes/rules.d"
	DefaultRulesFile            = "/tmp/holmes_rules.yaml"
	UploadRulesFile             = "/tmp/latest_rules.yaml"
)

type ProcessInfo struct {
	Handler          *exec.Cmd
	StartWithDefault bool
	StartModeUpdate  bool
	restartLock      *sync.Mutex
	runingLock       *sync.Mutex
}

func NewProcessInfo() *ProcessInfo {
	return &ProcessInfo{nil, true, false, new(sync.Mutex), new(sync.Mutex)}
}

func (p *ProcessInfo) RestartHolmesViaSignal() (err error) {
	p.restartLock.Lock()
	defer p.restartLock.Unlock()
	err = nil

	log.Printf("restart holmes(%d)\n", p.Handler.Process.Pid)
	// Signal Deal Reference https://scm.tensorsecurity.cn/tensorsecurity-rd/holmes/-/blob/bfc0021cdd96c9f0c13e2a2fb2c5fde3016af8ec/userspace/falco/falco.cpp#L1022-1048
	if p.StartModeUpdate {
		p.StartModeUpdate = false
		err = p.Handler.Process.Signal(syscall.SIGINT)
		return err
	}
	err = p.Handler.Process.Signal(syscall.SIGHUP)

	return err
}

func (p *ProcessInfo) StartHolmes(cmdLine string, ch chan<- error) {

	p.runingLock.Lock()
	defer p.runingLock.Unlock()

	log.Printf("start holmes: %s\n", cmdLine)
	name := strings.Split(cmdLine, " ")[0]
	argsList := strings.Split(cmdLine, " ")[1:]
	if p.StartWithDefault && !p.StartModeUpdate {
		argsList = append(argsList, "-r", DefaultRulesFile)
	} else {
		argsList = append(argsList, "-r", UploadRulesFile)
	}
	argsList = append(argsList, "-r", securityProfilesRulesFolder)
	log.Println(name, argsList)

	p.Handler = exec.Command(name, argsList...)
	p.Handler.Stderr = os.Stderr
	p.Handler.Stdout = os.Stdout
	err := p.Handler.Start()
	if err != nil {
		p.Handler = nil
		ch <- err
		return
	}
	err = p.Handler.Wait()
	p.Handler = nil

	ch <- err

}
