package registry

import "gitlab.com/piccolo_su/vegeta/pkg/logging"

func RegistryClientLog(format string, args ...interface{}) {
	logging.GetLogger().Trace().Msgf(format,args)
}
