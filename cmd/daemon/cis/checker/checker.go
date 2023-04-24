package checker

import (
	"context"
	"errors"
	"fmt"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/cis/pkg/check"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/cis/pkg/utils"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

type CheckerServiceConfig struct {
	Type string
}

const (
	HostType      = "host"
	ContainerType = "container"
)

var services = make(map[string]Creator)

type Creator func(config CheckerServiceConfig) (CheckerService, error)

func Register(name string, creator Creator) error {
	if creator == nil {
		return errors.New("could not register nil Creator")
	}
	if _, dup := services[name]; dup {
		return errors.New("could not register duplicate Creator: " + name)
	}
	services[name] = creator
	return nil
}

func GetServices() map[string]Creator {
	return services
}

// Open opens a service specified by a configuration.
func Open(cfg CheckerServiceConfig) (CheckerService, error) {
	driver, ok := services[cfg.Type]
	if !ok {
		return nil, fmt.Errorf("unknown Creator %q (forgotten configuration or import?)", cfg.Type)
	}
	logging.GetLogger().Debug().Msgf("Using %s checker", cfg.Type)
	return driver(cfg)
}

// CheckerService represents the required operations of a service
type CheckerService interface {
	// Start define works that service do
	Start(ctx context.Context) error

	RunChecks(ctx context.Context, path string) (check.Controller, error)

	CheckerType() string
	Name() string
}

func WriteOutput(controls *check.Controls) {
	var (
		noResults         = false
		includeTestOutput = true
		noRemediations    = false
		noSummary         = false
	)
	utils.PrettyPrint(controls, controls.Summary, noResults, includeTestOutput, noRemediations, noSummary)
}
