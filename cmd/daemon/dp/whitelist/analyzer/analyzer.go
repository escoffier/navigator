package analyzer

import (
	"fmt"
	"github.com/docker/docker/api/types"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/global"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/container"
	"gitlab.com/security-rd/go-pkg/logging"
	"os"
	"sync"
)

var (
	creatorLock       sync.Mutex
	creators          = make(map[Type]Creator)
	alternateCreators = make(map[Type]Creator)
)

type RegistrableComponentConfig struct {
	Type    Type
	Options map[string]interface{}
}

// Creator create analyzer instance
type Creator func(RegistrableComponentConfig) (Analyzer, error)

// Analyzer analyze path,get exec file list
type Analyzer interface {
	// Clean some clean job before analyze.eg.clean device after reboot
	Clean() error

	Type() Type

	Require(runtimeInfo types.Info) bool

	// AnalyzeWhiteList get all exec files
	AnalyzeWhiteList(runtime container.Runtime, runtimeInfo container.RuntimeInfo, image container.ImageInspect) (ExecFiles, error)
}

// Register used for analyzers
func Register(name Type, creator Creator) error {
	if creator == nil {
		return fmt.Errorf("could not register nil creator")
	}
	if _, dup := creators[name]; dup {
		return fmt.Errorf("could not register duplicate creator: %v", name)
	}
	creators[name] = creator
	return nil
}

func RegisterAlternate(name Type, creator Creator) error {
	if creator == nil {
		return fmt.Errorf("could not register nil creator")
	}
	if _, dup := alternateCreators[name]; dup {
		return fmt.Errorf("could not register duplicate creator: %v", name)
	}
	alternateCreators[name] = creator
	return nil
}

// Open used to create analyzer instance
func Open(cfg RegistrableComponentConfig) (Analyzer, error) {
	creatorLock.Lock()
	defer creatorLock.Unlock()
	creator, ok := creators[cfg.Type]
	if !ok {
		return nil, fmt.Errorf("unknown creator %q (forgotten configuration or import?)", cfg.Type)
	}
	return creator(cfg)
}

func OpenAlternate(cfg RegistrableComponentConfig) (Analyzer, error) {
	creatorLock.Lock()
	defer creatorLock.Unlock()
	creator, ok := alternateCreators[cfg.Type]
	if !ok {
		return nil, fmt.Errorf("unknown creator %q (forgotten configuration or import?)", cfg.Type)
	}
	return creator(cfg)
}

// Analyze generate exec file list, called by others
func Analyze(runtime container.Runtime, image container.ImageInspect) (ExecFiles, error) {
	runtimeInfo, err := runtime.RuntimeInfo()
	if err != nil {
		logging.Get().Err(err).Msg("failed to get runtime info")
		return nil, err
	}
	logging.Get().Debug().Interface("runtime info", runtimeInfo).Msg("get runtime info")

	modeImageTar := os.Getenv(global.DpScanModeEnv)

	if runtimeInfo.RuntimeType == "containerd" {
		modeImageTar = global.DpScanModeImageTar
	}

	if modeImageTar != global.DpScanModeImageTar {
		// create new analyzer by runtime.Driver
		a, err := Open(RegistrableComponentConfig{Type: Type(runtimeInfo.Driver)})
		if err == nil {
			return a.AnalyzeWhiteList(runtime, runtimeInfo, image)
		} else {
			logging.Get().Warn().Str("type", runtimeInfo.Driver).Msg("failed to create normal analyzer,chose alternate")
		}
	}

	// chose alternate analyzer when specified by env or create normal analyzer err
	a, err := OpenAlternate(RegistrableComponentConfig{Type: TypeImageTar})
	if err != nil {
		logging.Get().Err(err).Str("type", string(TypeImageTar)).Msg("failed to create alternate analyzer")
		return nil, err
	}

	return a.AnalyzeWhiteList(runtime, runtimeInfo, image)
}

// Clean remove analyzer dependence(eg. devicemapper's snap) after reboot
func Clean(runtime container.Runtime) error {
	info, err := runtime.RuntimeInfo()
	if err != nil {
		logging.Get().Err(err).Msg("failed to get runtime info")
		return err
	}
	a, err := Open(RegistrableComponentConfig{Type: Type(info.Driver)})
	if err != nil {
		logging.Get().Err(err).Msg("failed to create analyzer")
		return err
	}

	return a.Clean()
}

func DumpExecFileList(filename string, whitelist ExecFiles) error {
	output := ""
	for k, v := range whitelist {
		output = output + fmt.Sprintf("%s %s \n", k, v)
	}
	return os.WriteFile(filename, []byte(output), os.ModePerm)
}
