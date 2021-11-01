// Package register defines the  models and a common interface for
// registry implementations.
package register

import (
	"errors"
	"fmt"
	"sync"

	"github.com/boltdb/bolt"
)

// RegistrableComponentConfig is a configuration block that can be used to
// determine which registrable component should be initialized and pass custom
// configuration to it.
type RegistrableComponentConfig struct {
	Type    string
	Options map[string]interface{}
}

var drivers = make(map[string]Driver)

// Driver is a function that connects a registry specified by its client driver type and specific
// configuration.
type Driver func(RegistrableComponentConfig, *bolt.DB, string) (Registry, error)

// Register makes a Constructor available by the provided name.
//
// If this function is called twice with the same name or if the Constructor is
// nil, it panics.
func Register(name string, driver Driver) error {
	if driver == nil {
		return errors.New("could not register nil Driver")
	}
	if _, dup := drivers[name]; dup {
		return errors.New("could not register duplicate Driver: " + name)
	}
	drivers[name] = driver
	return nil
}

func GetDriversName() []string {
	names := make([]string, 0)
	for k := range drivers {
		names = append(names, k)
	}
	return names
}

// Open opens a registry specified by a configuration.
func Open(cfg RegistrableComponentConfig, db *bolt.DB, dbPath string) (Registry, error) {
	driver, ok := drivers[cfg.Type]
	if !ok {
		return nil, fmt.Errorf("unknown Driver %q (forgotten configuration or import?)", cfg.Type)
	}
	return driver(cfg, db, dbPath)
}

// Registry represents the required operations on a registry
type Registry interface {
	Updata(wg *sync.WaitGroup)
}
