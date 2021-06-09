package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/config"

	log "github.com/sirupsen/logrus"
	"gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/netInfo"
	"gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/scheduler"
)

func NetInit(dbHost, dbUser, dbPwd, dbName, dbPort string) error {
	db, err := netInfo.NewConnPgDB(dbHost, dbUser, dbPwd, dbName, dbPort)
	if err != nil {
		return fmt.Errorf("Failed to initialize db connection, %v", err)
	}

	err = db.InitMigration()
	if err != nil {
		return fmt.Errorf("Failed to make initial migrations, %v", err)
	}

	k8sResSync, err := netInfo.NewK8sResourceSyncer()
	if err != nil {
		return fmt.Errorf("Failed to initialize k8s resource sycner, : %w", err)
	}

	err = k8sResSync.StartK8sServiceSyncer()
	if err != nil {
		return fmt.Errorf("listen k8s event failed, %v.", err)
	}

	flowsession, err := netInfo.NewFlowSession(k8sResSync, db)
	if err != nil {
		return fmt.Errorf("Failed to initialize flow session, %w", err)
	}

	stopCron := make(chan struct{})
	flowsession.Start(stopCron)

	close(stopCron)

	return nil
}

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
	dbHost := flag.String("dbHost", "tensorsec-postgresql", "PostgreSQL host")
	dbUser := flag.String("dbUser", "postgres", "PostgreSQL username")
	dbPwd := flag.String("dbPassword", "password", "PostgreSQL password")
	dbName := flag.String("dbName", "postgres", "PostgreSQL database name")
	dbPort := flag.String("dbPort", "5432", "PostgreSQL port")

	flag.Parse()

	if *debug {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}

	//print log
	// log.Infof("host = %s, user = %s, pwd = %s, name = %s, port = %s, my-ip = %v.", *dbHost, *dbUser, *dbPwd, *dbName, *dbPort, os.Getenv("MY_POD_IP"))
	// err := NetInit(*dbHost, *dbUser, *dbPwd, *dbName, *dbPort)
	// if err != nil {
	// 	log.Errorf("net init failed, %v.", err)
	// }

	log.Infof("configFilename = %s, exitDelay= %v.", *configFilename, *exitDelay)

	go func() {
		err := NetInit(*dbHost, *dbUser, *dbPwd, *dbName, *dbPort)
		if err != nil {
			log.Errorf("net init failed, %v.", err)
		}
	}()

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
