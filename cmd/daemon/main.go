package main

import (
	"flag"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/netflow"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/ruleMetrics"
)

func NetInit(dbHost, dbUser, dbPwd, dbName, dbPort string) error {
	db, err := netflow.NewConnPgDB(dbHost, dbUser, dbPwd, dbName, dbPort)
	if err != nil {
		return fmt.Errorf("Failed to initialize db connection, %v", err)
	}

	hostName := os.Getenv("MY_NODE_NAME")
	if hostName == "" {
		hostName = "Unknown"
	}

	err = db.InitMigration()
	if err != nil {
		return fmt.Errorf("Failed to make initial migrations, %v", err)
	}

	ruleMetricsClient, err := ruleMetrics.NewRuleMetricsClient(db.Db, hostName)
	if err != nil {
		log.Errorf("Failed to initialize rule metrics client: %w", err)
	} else {
		ruleMetricsClient.Start()
	}

	k8sResSync, err := netflow.NewK8sResourceSyncer()
	if err != nil {
		return fmt.Errorf("Failed to initialize k8s resource sycner, : %w", err)
	}

	err = k8sResSync.StartK8sServiceSyncer()
	if err != nil {
		return fmt.Errorf("listen k8s event failed, %v.", err)
	}

	flow, err := netflow.NewFlowSession(k8sResSync, db)
	if err != nil {
		return fmt.Errorf("Failed to initialize flow session, %w", err)
	}

	stopCron := make(chan struct{})

	flow.Start(stopCron)

	close(stopCron)

	return nil
}

func main() {

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

	err := NetInit(*dbHost, *dbUser, *dbPwd, *dbName, *dbPort)
	if err != nil {
		log.Errorf("net init failed, %v.", err)
	}
}
