package main

import (
	"flag"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"gitlab.com/piccolo_su/vegeta/cmd/holmes/holmes-scheduler/decode"
	"gitlab.com/piccolo_su/vegeta/cmd/holmes/holmes-scheduler/helper"
	"gitlab.com/piccolo_su/vegeta/cmd/holmes/holmes-scheduler/watch"
)

const (
	// defaultThrPath = "/tensorsec-holmes-rules.thr"
	defaultThrPath = "/holmes-rules.thr"
)

func closeRules(streamBytes []byte, closeRules []string) []byte {
	rulesStr := string(streamBytes)
	log.Info("close rules: ", closeRules)
	addStr := "  enabled: false\n"
	for _, v := range closeRules {
		repStr := "- rule: " + v + "\n"
		index := strings.Index(rulesStr, repStr)
		if index < 0 {
			continue
		}
		rulesStr = strings.Replace(rulesStr, repStr, repStr+addStr, len(addStr))

	}
	retBytes := []byte(rulesStr)
	return retBytes
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

func prepareRulesFile(thrPath string, outputPath string, closedRules []string) error {

	rulesContext, err := decode.DoRulesDecode(thrPath)
	if err != nil {
		log.Error(err)
	}

	writeBytes := closeRules(rulesContext, closedRules)

	t := time.NewTicker(1 * time.Minute)
	defer t.Stop()
	for ; true; <-t.C {
		err = holmeshelper.SendRulesToEventCenter(writeBytes)
		if err != nil {
			log.Error(err)
		} else {
			break
		}
	}

	return saveRulesFile(writeBytes, outputPath)
}

func main() {

	consoleAddr := "http://console-svc:8889"
	if len(os.Getenv("IS_MAIN_CLUSTER")) > 0 && os.Getenv("IS_MAIN_CLUSTER") == "true" {
		consoleAddr = os.Getenv("CONSOLE_INTERNAL_URL")
	} else {
		consoleAddr = os.Getenv("CONSOLE_EXTERNAL_URL")
	}

	url := consoleAddr
	suffix := "/api/openapi/ATTCK/latestData"

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

	if *debug {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}

	consoleUpdateC := make(chan int)
	configmapUpdateC := make(chan int)
	errorC := make(chan error)
	quit := make(chan int)

	hp := holmeshelper.NewProcessInfo()
	r := watch.NewHttpRequest(url + suffix)

	go watch.ConfigmapWatchInit(configmapUpdateC, errorC)
	go r.RulesUpdateLoop(consoleUpdateC, errorC)

	var err error

	for {
		err = nil
		if hp.Handler == nil {
			if hp.StartWithDefault {
				err = prepareRulesFile(defaultThrPath, holmeshelper.DefaultRulesFile, r.CloseRules)
			} else {
				err = prepareRulesFile(watch.UploadThrPath, *outputRulesFilename, r.CloseRules)
			}
			if err != nil {
				log.Error(err)
				if hp.StartWithDefault {
					log.Error("try restart container...")
					os.Exit(0)
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
				prepareRulesFile(watch.UploadThrPath, *outputRulesFilename, r.CloseRules)

			}
			log.Info("restart holmes because upload update... ")
			hp.RestartHolmesViaSignal()

		case <-configmapUpdateC:
			if hp.StartWithDefault {
				prepareRulesFile(defaultThrPath, holmeshelper.DefaultRulesFile, r.CloseRules)
			} else {
				prepareRulesFile(watch.UploadThrPath, *outputRulesFilename, r.CloseRules)
			}
			log.Info("restart holmes because configmap update... ")
			hp.RestartHolmesViaSignal()

		case err := <-errorC:
			log.Error("===========holmes running error============")
			log.Error(err)
		case <-quit:
			log.Error("holmes exit, try restart container")
			os.Exit(0)
		}
	}

}
