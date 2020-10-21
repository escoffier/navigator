package producer

import (
	"os"
	"os/signal"
	"testing"

	log "github.com/sirupsen/logrus"
)

func TestNet(t *testing.T) {
	producersInfo := []ProducerInfoT{
		{
			ProducerType:    Net,
			ProducerName:    "inet_bind",
			ProducerFilters: []FilterT{},
		},
		{
			ProducerType:    Net,
			ProducerName:    "inet_listen",
			ProducerFilters: []FilterT{},
		},
		{
			ProducerType:    Net,
			ProducerName:    "inet_accept",
			ProducerFilters: []FilterT{},
		},
		{
			ProducerType:    Net,
			ProducerName:    "inet_shutdown",
			ProducerFilters: []FilterT{},
		},
		{
			ProducerType:    Net,
			ProducerName:    "tcp_v4_connect",
			ProducerFilters: []FilterT{},
		},
		{
			ProducerType:    Net,
			ProducerName:    "tcp_v6_connect",
			ProducerFilters: []FilterT{},
		},
		{
			ProducerType:    Net,
			ProducerName:    "udp_sendmsg",
			ProducerFilters: []FilterT{},
		},
	}
	syscallINFOS := []ProducerInfoT{
		{
			ProducerType:    Syscall,
			ProducerName:    "sync",
			ProducerFilters: []FilterT{},
		},
	}
	m := NewManager(syscallINFOS, producersInfo)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	m.Init()
	m.Start()

	<-sig
	log.Error("Catch sigInt")
	m.Stop()
}
