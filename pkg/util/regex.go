package util

import (
	"github.com/dlclark/regexp2"
	"gitlab.com/security-rd/go-pkg/logging"
)

func MatchName(name string) bool {
	re := regexp2.MustCompile(`^[\p{Han}a-zA-Z0-9-_]+$`, regexp2.None)
	ok, err := re.MatchString(name)
	if err != nil {
		logging.Get().Error().Err(err).Str("name", name).Msg("re.MatchString fails")
		return false
	}
	return ok
}

func MatchEnName(name string) bool {
	re := regexp2.MustCompile(`^[a-zA-Z0-9-_]+$`, regexp2.None)
	ok, err := re.MatchString(name)
	if err != nil {
		logging.Get().Error().Err(err).Str("name", name).Msg("re.MatchString fails")
		return false
	}
	return ok
}
