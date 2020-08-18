package dockerbench

import (
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/scap"
)

var log *logging.Logger

func init() {
	log = logging.GetLogger()
	scap.RegisterChecker("docker", &DockerBench{})
}

//DockerBench Docker bench data struct
type DockerBench struct {
}

//Check Check call for Checker interface
func (d *DockerBench) Check() (interface{}, error) {
	log.Info().Msg("Docker bench module start checking")
	return nil, nil
}

//InitializeChecker Initialize Checker for Docker bench
func (d *DockerBench) InitializeChecker(c *model.ScapTask) error {
	log.Info().Msg("Docker bench module initialized")
	return nil
}
