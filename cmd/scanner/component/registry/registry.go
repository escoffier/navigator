// Package registry defines the  models and a common interface for
// registry implementations.
package registry

import (
	"errors"
	"fmt"
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
type Driver func(RegistrableComponentConfig) (Registry, error)

// ImageListExtender is a function that can do some stuff when sync one image
type ImageListExtender func(image Image) error

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

// Open opens a registry specified by a configuration.
func Open(cfg RegistrableComponentConfig) (Registry, error) {
	driver, ok := drivers[cfg.Type]
	if !ok {
		return nil, fmt.Errorf("unknown Driver %q (forgotten configuration or import?)", cfg.Type)
	}
	return driver(cfg)
}

// Registry represents the required operations on a registry
type Registry interface {
	// // ListRepos returns the entire list of repository.
	// ListRepos() ([]string, error)
	//
	// // ListRepoTags returns the repo tags
	// ListRepoTags(string) ([]string, error)

	CheckProject(projectName string) error

	CreateProject(projectName string, public bool) error

	GetImage(projectName, fullRepoName, tag string) (*Image, error)

	// DeleteImages delete special image
	DeleteImages(projectName, repoName, digest string) error

	// ListImages return all images
	ListImages(extender ImageListExtender) ([]Image, error)
}
