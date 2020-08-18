package hostbench

import (
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/scap"
)

var log *logging.Logger

func init() {
	log = logging.GetLogger()
	scap.RegisterChecker("host", &HostBench{})
}

//HostBench Host-base Bench Test
type HostBench struct {
}

//Check Host bench Check
func (d *HostBench) Check() (interface{}, error) {
	log.Info().Msg("HostBench module start checking")
	return nil, nil
}

//InitializeChecker Initialize Checker for Host Bench
func (d *HostBench) InitializeChecker(c *model.ScapTask) error {
	log.Info().Msg("HostBench module initialized")
	return nil
}
