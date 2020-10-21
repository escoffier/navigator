package scheduler

import (
	"gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/constant"
	"gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/consumer"
	"gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/producer"
	log "github.com/sirupsen/logrus"
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
	cs.newConumsers(consumersInfo)
	for range cs.consumers {
		cs.combinedChan = append(cs.combinedChan, make(chan constant.Data))
	}
	cs.quitChan = make(chan struct{})
}

func (cs *CombineSchedule) newConumsers(consumersInfo []string) error {
	for _, v := range consumersInfo {
		var c consumer.Consumer
		switch v {
		case "Print":
			c = consumer.NewPrintConsumer()
		case "Count":
			c = consumer.NewCountConsumer()
		case "Collect":
			c = consumer.NewCollectConsumer()
        case "Json":
            c = consumer.NewJsonConsumer ()
        case "Socket":
            c = consumer.NewSocketConsumer ()
		}

		// consumer init at "Schedule" method using "consumer.Init(cs.combinedChan[i])"
		cs.consumers = append(cs.consumers, c)
	}
	return nil
}

// Stop producers and consumers
func (cs *CombineSchedule) Stop() {
	cs.Manager.Stop()

	for _, cc := range cs.combinedChan {
		close(cc)
	}

	for i, c := range cs.consumers {
		c.Stop()
		log.Errorf("Stop consumer %d", i)
	}
	<-cs.quitChan
}

func (cs *CombineSchedule) Schedule() {
	log.Error("Scheduler started.")
	// go func() {
	// 	cs.Manager.NsMap.RefreshNsMapBackground(1 * time.Second)
	// }()

	// Start Consumer fisrt
	for i, consumer := range cs.consumers {
		consumer.Init(cs.combinedChan[i])
		go consumer.Consume(cs.Manager.NsMap)
	}

	// Schedule
	go func() {
		for v := range cs.Manager.DataChan {
			for _, cc := range cs.combinedChan {
				cc <- v
			}
		}
		cs.quitChan <- struct{}{}
	}()

	// Start Producer
	cs.Manager.Init()
// 	cs.Manager.Start()
	cs.Manager.StartChronologicalPoll()
}
