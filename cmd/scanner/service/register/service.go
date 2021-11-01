package register

import (
	"context"
	"errors"
	"fmt"

	flag2 "gitlab.com/piccolo_su/vegeta/cmd/scanner/flag"
)

type ScannerServiceConfig struct {
	Type    string
	Options *flag2.ScannerOpts
}

var services = make(map[string]Creator)

type Creator func(config ScannerServiceConfig) (ScannerService, error)

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
func Open(cfg ScannerServiceConfig) (ScannerService, error) {
	driver, ok := services[cfg.Type]
	if !ok {
		return nil, fmt.Errorf("unknown Creator %q (forgotten configuration or import?)", cfg.Type)
	}
	return driver(cfg)
}

// ScannerService represents the required operations of a service
type ScannerService interface {
	// Start define works that service do
	Start(ctx context.Context) error

	// Stop define works that will be done when service quit
	Stop(ctx context.Context) error
}
