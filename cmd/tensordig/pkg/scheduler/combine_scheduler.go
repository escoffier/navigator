package scheduler

import (
	"runtime/debug"

	log "github.com/sirupsen/logrus"
	"gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/constant"
	"gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/consumer"
	"gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/producer"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

type CombineSchedule struct {
	Manager      *producer.Manager
	consumers    []consumer.Consumer
	combinedChan []chan constant.Data
	quitChan     chan struct{}
}

func (cs *CombineSchedule) Init(syscallPIFS, netPINFS []producer.ProducerInfoT,
	consumersInfo []string) {

	cs.Manager = producer.NewManager(syscallPIFS, netPINFS)
	cs.newConsumers(consumersInfo)
	for range cs.consumers {
		cs.combinedChan = append(cs.combinedChan, make(chan constant.Data))
	}
	cs.quitChan = make(chan struct{})
}

func (cs *CombineSchedule) newConsumers(consumersInfo []string) error {
	for _, v := range consumersInfo {
		var c consumer.Consumer
		switch v {
		case "Json":
			c = consumer.NewJsonConsumer()
		case "SeccompGenerate":
			c = consumer.NewSeccompGeneration()
		case "SeccompPrevent":
			c = consumer.NewSeccompPrevent()
		}

		// consumer init at "Schedule" method using "consumer.Init(cs.combinedChan[i])"
		if c != nil {
			cs.consumers = append(cs.consumers, c)
		}
	}
	return nil
}

// Stop producers and consumers
func (cs *CombineSchedule) Stop() {
	cs.Manager.Stop()

	for i := range cs.combinedChan {
		log.Infof("Closing customer data channel %d", i)
		close(cs.combinedChan[i])
	}

	for i, c := range cs.consumers {
		log.Infof("Stop consumer %d", i)
		c.Stop()
	}
	<-cs.quitChan
}

func (cs *CombineSchedule) Schedule() {
	log.Info("Scheduler started.")
	// go func() {
	// 	cs.Manager.NsMap.RefreshNsMapBackground(1 * time.Second)
	// }()

	// Start Consumer fisrt
	for i, consumer := range cs.consumers {
		err := consumer.Init(cs.combinedChan[i])
		if err != nil {
			panic(err)
		}
		go consumer.Consume(cs.Manager.NsMap)
	}
	log.Info("Consumers started.")

	// Schedule
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Msgf("Panic : %v. stack: %s", r, debug.Stack())
			}
		}()

		for v := range cs.Manager.DataChan {
			for _, cc := range cs.combinedChan {
				cc <- v
			}
		}
		cs.quitChan <- struct{}{}
	}()

	// Start Producer
	cs.Manager.Init()
	log.Info("Manager started.")

	// 	cs.Manager.Start()
	cs.Manager.Start()
	log.Info("Regular poll started.")
}
