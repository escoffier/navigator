package producer

import (
	"testing"
	"time"

	bpf "github.com/iovisor/gobpf/bcc"
)

func TestExit(t *testing.T) {
	p := NewExitProducer()
	module := bpf.NewModule(exitCode, []string{})
	p.Init(module)
	go p.Start()
	time.Sleep(10 * time.Second)
	p.Stop()
}
