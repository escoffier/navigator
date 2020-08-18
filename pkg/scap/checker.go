package scap

import (
	"fmt"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

var checkers = make(map[string]Checker)
var log *logging.Logger

func init() {
	log = logging.GetLogger()
}

// RegisterChecker makes a Checker available by the provided name.
func RegisterChecker(name string, d Checker) {
	if name == "" {
		log.Error().Msg("empty checker name ")
	}
	if d == nil {
		log.Error().Msg("could not register a nil Driver")
	}

	if _, dup := checkers[name]; dup {
		log.Error().Msgf("duplicate driver named as %s", name)
	}

	checkers[name] = d
}

//ListChecker List all checkers name
func ListChecker() {
	log.Info().Msg("Listing Checkers: \n")
	for name, item := range checkers {
		log.Info().Msgf("Checker: %s, %v", name, item)
	}
}

//GetChecker Get the checker
func GetChecker(name string) (e Checker, err error) {
	e, ok := checkers[name]
	if !ok {
		err = fmt.Errorf("no checker %s registered", name)
	}

	return
}
