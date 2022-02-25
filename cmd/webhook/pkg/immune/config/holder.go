package config

import (
	"fmt"
	"io/ioutil"
	"runtime/debug"
	"sync"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/driftprevention/v1alpha1"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gopkg.in/yaml.v2"
	"gorm.io/gorm"
	"k8s.io/client-go/kubernetes"
)

var (
	errFileRead  = fmt.Errorf("failed to read config file")
	errUnmarshal = fmt.Errorf("failed to unmarshal config data")
)

// NewReloadingConfig sets up a new holder that periodically reloads the configuration from disk.
// The reloaded configuration then replaces the current version in memory.
func NewReloadingConfig(path string, db *gorm.DB, k8sCli *kubernetes.Clientset, reloadConfig *ReloadConfig) (*Holder, error) {
	holder := &Holder{
		path:    path,
		DB:      db,
		K8sCli:  k8sCli,
		mu:      &sync.RWMutex{},
		current: nil,
	}

	if err := holder.Reload(); err != nil {
		return nil, err
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Msgf("Panic : %v. stack: %s", r, debug.Stack())
			}
		}()

		for true {
			sleepDuration := reloadConfig.ReloadInterval
			if err := holder.Reload(); err != nil {
				logging.GetLogger().Err(err).Msg("failed to reload config")
				sleepDuration = reloadConfig.FailureRetryInterval
			}
			time.Sleep(sleepDuration)
		}
	}()

	return holder, nil
}

// Holder encapsulates te current configuration.
type Holder struct {
	path    string
	DB      *gorm.DB
	K8sCli  *kubernetes.Clientset
	mu      *sync.RWMutex
	current *v1alpha1.PodPresetSpec
}

// Reload forces a reload of the configuration the holder was configured with.
func (c *Holder) Reload() error {
	data, err := ioutil.ReadFile(c.path)
	if err != nil {
		return errFileRead
	}

	newVersion := &v1alpha1.PodPresetSpec{}
	if err := yaml.Unmarshal(data, newVersion); err != nil {
		logging.GetLogger().Err(err).Msgf("failed to unmarshal config data")
		return errUnmarshal
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.current = newVersion
	return nil
}

// Get returns the current active version of the configuration.
func (c *Holder) Get() *v1alpha1.PodPresetSpec {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.current
}
