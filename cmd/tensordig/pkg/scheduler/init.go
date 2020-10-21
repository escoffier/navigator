package scheduler

import (
	"gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/producer"
)

type schedulerType int

const (
	COMBINE schedulerType = iota
)

// Scheduler schedule p and c
type Scheduler interface {
	// Init Create producer and conumser
	Init(producersInfo producer.ProducerInfoT, consumersInfo []string) error
	Schedule() error
	Stop() error
}

// NewScheduler
func NewScheduler(schedulerType) Scheduler {
	return nil
}
