package main

import (
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/stan.go"
	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

const (
	associatedSubject = "tensorsec_associated_events"
	queueName         = "tensorsec_holmes_palace"
)

var (
	stanConnection stan.Conn
)

func initStan(podName string) error {
	stanURL := os.Getenv("STAN_URL")
	if stanURL == "" {
		logging.GetLogger().Warn().Msg("env STAN_URL not found")
		return errors.New("get STAN address failed.")
	}
	nc, err := nats.Connect(fmt.Sprintf("nats://%s", stanURL), nats.MaxReconnects(5), nats.ReconnectBufSize(64*1024), nats.ReconnectWait(500*time.Millisecond))
	if err != nil {
		return errors.New("Failed to connect to NATS")
	}
	stanConn, err := stan.Connect("tensorsec", podName, stan.NatsConn(nc))
	if err != nil {
		errors.New("Failed to connect to STAN")
	}

	stanConnection = stanConn
	return nil
}

func handleAssocatedEvents(m *stan.Msg) {

}

func main() {
	podName := os.Getenv("MY_POD_NAME")
	if podName == "" {
		podName = "Unknown"
	}
	err := initStan(podName)
	if err != nil {
		logging.GetLogger().Err(err).Msg("init stan error")
		panic(err)
	}

	subscription, err := stanConnection.QueueSubscribe(associatedSubject, queueName, handleAssocatedEvents, stan.StartWithLastReceived(), stan.DurableName(queueName))
	if err != nil {
		logging.GetLogger().Err(err).Msg("subscribe error.")
		panic(err)
	}

	defer subscription.Close()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, os.Kill)
	<-sigChan
}
