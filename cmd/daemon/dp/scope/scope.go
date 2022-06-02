package scope

import "fmt"

type RuleParam map[string]interface{}

type Rule interface {
	Match(param RuleParam) (bool, error)
}

type RuleConfig struct {
	Type    string
	Options map[string]interface{}
}

var drivers = make(map[string]Driver)

type Driver func(runtime RuleConfig) (Rule, error)

func Register(name string, driver Driver) error {
	if driver == nil {
		return fmt.Errorf("could not register nil dirver")
	}
	if _, dup := drivers[name]; dup {
		return fmt.Errorf("could not register duplicate Driver: " + name)
	}
	drivers[name] = driver
	return nil
}

func Open(cfg RuleConfig) (Rule, error) {
	driver, ok := drivers[cfg.Type]
	if !ok {
		return nil, fmt.Errorf("unknown Driver %q (forgotten configuration or import?)", cfg.Type)
	}
	return driver(cfg)
}
