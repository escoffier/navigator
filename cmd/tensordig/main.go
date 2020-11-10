package main

import (
	"flag"
	"os"
	"os/signal"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/config"

	log "github.com/sirupsen/logrus"
	"gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/scheduler"
)

func main() {
	configFilename := flag.String("config",
		"example.yaml",
		"Config file for tensordig to work, `example.yaml` is an example.")
	exitDelay := flag.Int("exit-delay",
		0,
		"Run and exit after [exit-delay] seconds. Default is 0.")
	debug := flag.Bool("debug",
		false,
		"Run in debug mode with extended logging")
	flag.Parse()

	if *debug {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}

	cs := &scheduler.CombineSchedule{}
	syscallPIFS, netPIFS, consumersInfo, err := config.ParseYaml(configFilename)
	if err != nil {
		log.Fatalf("YAML static verify failed: %v", err)
	}
	now := time.Now()
	cs.Init(syscallPIFS, netPIFS, consumersInfo)
	cs.Schedule()
	if *exitDelay == 0 {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, os.Kill)
		<-sigChan
		log.Error("sigInt catched.")
	} else {
		time.Sleep(time.Duration(*exitDelay) * time.Second)
		log.Infof("Time to quit now...")
	}
	cs.Stop()
	log.Infof("Quit scheduler successfully.")
	log.Infof("Time duration: %s", time.Since(now))
}
