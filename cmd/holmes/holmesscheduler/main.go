package main

import (
	"fmt"
	"os"

	"github.com/rs/zerolog"
	log "github.com/sirupsen/logrus"
	flag "github.com/spf13/pflag"
	"gitlab.com/piccolo_su/vegeta/cmd/holmes/holmesscheduler/decode"
	"gitlab.com/piccolo_su/vegeta/cmd/holmes/holmesscheduler/holmesengine"
	"gitlab.com/piccolo_su/vegeta/cmd/holmes/holmesscheduler/watch"
	"gitlab.com/security-rd/go-pkg/logging"
	_ "go.uber.org/automaxprocs"
)

const (
	defaultThrPath = "/holmes-rules.thr"
)

var (
	namespaceMutator holmesengine.MutationFunc
	loggingOptions   *logging.Options
)

func init() {
	loggingOptions = logging.NewLoggingOptions()
	loggingOptions.AddFlags(flag.CommandLine)
}

func saveRulesFile(writeBytes []byte, path string) error {
	fp, err := os.Create(path)
	if err != nil {
		return err
	}
	defer fp.Close()
	_, err = fp.Write(writeBytes)
	if err != nil {
		return err
	}
	return fp.Sync()
}

func prepareRulesFile(thrPath string, outputPath string, closedRules map[string]struct{}) ([]byte, error) {
	rulesContext, err := decode.DoRulesDecode(thrPath)
	if err != nil {
		logging.Get().Err(err).Msgf("decode error. path: %s", thrPath)
		return nil, err
	}

	// DEBUG
	logging.Get().Trace().Msgf("closedFiles: %v", closedRules)
	// rules swith mutation
	rulesSwitchMutate := holmesengine.GetRuleSwitchMutationFunc(closedRules)
	writeBytes, err := holmesengine.RulesMutate(rulesContext, rulesSwitchMutate, namespaceMutator)
	if err != nil {
		return nil, err
	}
	// DEBUG
	logging.Get().Trace().Msgf("after mutation: %s", writeBytes)

	return writeBytes, saveRulesFile(writeBytes, outputPath)
}

func main() {
	clusterAddr := os.Getenv("CLUSTER_MANAGER_URL")
	if clusterAddr == "" {
		logging.Get().Panic().Msg("env CLUSTER_MANAGER_URL not found")
	}

	myNamespace := os.Getenv("MY_POD_NAMESPACE")
	if len(myNamespace) == 0 {
		myNamespace = "tensorsec"
	}
	namespaceMutator = holmesengine.GetTensorsecNamespaceChange(myNamespace)

	outputRulesFilename := flag.String("output",
		"/tmp/holmes_rules.yaml",
		"Binary for holmes update, `/tmp/holmes_rules.yaml` is an example.")
	cmdLineArgs := flag.String("holmes-args",
		"/usr/bin/holmes --cri /run/containerd/containerd.sock -K /var/run/secrets/kubernetes.io/serviceaccount/token -k https://$(KUBERNETES_SERVICE_HOST) -pk",
		"Holmes start args")
	debug := flag.Bool("debug",
		false,
		"Run in debug mode with extended logging")

	flag.Parse()

	if errs := loggingOptions.Validate(); len(errs) > 0 {
		logging.Get().Panic().Err(fmt.Errorf("%v", errs)).Msg("")
	}

	// 建议移除debug
	// 使用log-level调节日志输出等级
	if *debug || os.Getenv("DEBUG_MODE") == "1" {
		log.SetLevel(log.DebugLevel)
		loggingOptions.Level = int(zerolog.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}

	loggingOptions.SetConsoleWriterWrapper(logging.ConsoleCallerWriter)
	logging.ReplaceLogger(loggingOptions)

	consoleUpdateC := make(chan struct{})
	configmapUpdateC := make(chan struct{})
	errorC := make(chan error)
	quit := make(chan int)

	hp := holmesengine.NewProcessInfo()
	r := watch.NewHTTPRequest(clusterAddr)

	go watch.ConfigmapWatchInit(configmapUpdateC, errorC)
	go r.RulesUpdateLoop(consoleUpdateC, errorC)

	var err error

	for {
		err = nil
		if hp.Handler == nil {
			if hp.StartWithDefault {
				_, err = prepareRulesFile(defaultThrPath, holmesengine.DefaultRulesFile, r.CloseRules())
				if err != nil {
					logging.Get().Err(err).Msgf("parepare rules file error. thr path: %s", watch.UploadThrPath)
				}
			} else {
				_, err = prepareRulesFile(watch.UploadThrPath, *outputRulesFilename, r.CloseRules())
				if err != nil {
					logging.Get().Err(err).Msgf("parepare rules file error. thr path: %s", watch.UploadThrPath)
				}
			}

			if err != nil {
				logging.Get().Err(err).Msg("prepare rules error")
				if hp.StartWithDefault {
					log.Error("try restart container...")
					os.Exit(1)
				}
				hp.StartWithDefault = true
				continue
			}
			go hp.StartHolmes(*cmdLineArgs, errorC)
		}

		select {

		case <-consoleUpdateC:
			if hp.StartWithDefault {
				hp.StartModeUpdate = true
				hp.StartWithDefault = false
			} else {
				_, preErr := prepareRulesFile(watch.UploadThrPath, *outputRulesFilename, r.CloseRules())
				if preErr != nil {
					logging.Get().Err(preErr).Msgf("parepare rules file error. thr path: %s", watch.UploadThrPath)
				}
			}
			logging.Get().Info().Msg("restart holmes because upload update... ")
			if rerr := hp.RestartHolmesViaSignal(); rerr != nil {
				logging.Get().Err(rerr).Msg("Restart holmes error")
			}

		case <-configmapUpdateC:
			if hp.StartWithDefault {
				_, perr := prepareRulesFile(defaultThrPath, holmesengine.DefaultRulesFile, r.CloseRules())
				if perr != nil {
					logging.Get().Err(perr).Msg("prepare rules file error when configmap update. try restart container")
					os.Exit(1)
				}
			} else {
				_, perr := prepareRulesFile(watch.UploadThrPath, *outputRulesFilename, r.CloseRules())
				if perr != nil {
					logging.Get().Err(perr).Msg("prepare rules file error when configmap update. update fail.")
					continue
				}
			}
			logging.Get().Info().Msg("restart holmes because configmap update... ")
			if rerr := hp.RestartHolmesViaSignal(); rerr != nil {
				logging.Get().Err(rerr).Msg("Restart holmes error")
			}

		case err := <-errorC:
			logging.Get().Err(err).Msg("===========holmes running error============")
		case <-quit:
			logging.Get().Error().Msg("holmes exit, try restart container")
			os.Exit(0)
		}
	}

}
