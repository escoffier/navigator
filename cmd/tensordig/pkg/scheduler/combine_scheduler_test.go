package scheduler

import (
	"os"
	"os/signal"
	"testing"

	"gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/producer"

	log "github.com/sirupsen/logrus"
)

func TestCombineScheduler(t *testing.T) {
	cs := &CombineSchedule{}
	producersInfo := []string{"open", "sync"}
	producersFilters := [][]producer.FilterT{
		[]producer.FilterT{
			{
				Field:     "filename",
				Operation: producer.FEqualTo,
				ValueStr:  "/etc/passwd",
			},
			{
				Field:     "flags",
				Operation: producer.FEqualTo,
				ValueStr:  "0",
			},
		},
		nil,
	}
	consumersInfo := []string{""}
	cs.Init(producersInfo, consumersInfo, producersFilters)
	cs.Schedule()
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, os.Kill)
	<-sigChan
	log.Error("sigInt catched.")
	cs.Stop()
}
