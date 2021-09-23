package main

import (
	"flag"
	"fmt"
	"os"
)

var (
	postgreDb   *PostgreDB
	TaskID      string
	NodeName    string
	ClusterID   string
	ClusterAddr string
)

const (
	ConsoleUrlPath = "/internal/scap/scanResults"
)

func main() {
	// print debug log
	fmt.Printf("docker bench tool start......\n")

	outputfile := flag.String("outputfile", "", "scan result data")
	flag.Parse()

	if *outputfile == "" {
		fmt.Printf("can not get output file!\n")
		return
	}

	//postgreDb, err = NewConnPostgreDB()
	//if err != nil {
	//	fmt.Printf("connect posgreDB failed, error : %v\n", err)
	//	return
	//}
	//defer postgreDb.Close()

	//get env
	TaskID = os.Getenv("CHECK_ID")
	NodeName = os.Getenv("NODE_NAME")
	ClusterID = os.Getenv("CLUSTER_ID")
	ClusterAddr = os.Getenv("CLUSTER_ADDR")
	fmt.Printf("TaskID : %s, NodeName : %s, ClusterID : %s.\n", TaskID, NodeName, ClusterID)

	clusterManager := fmt.Sprintf("%s/internal/cluster", ClusterAddr)
	consoleUrl, err := GetConsoleUrl(clusterManager)
	if err != nil {
		fmt.Printf("get console url failed, %s, %v.\n", clusterManager, err)
		return
	}

	// parse scan result
	var scandata ScanInfo
	err = scandata.ParseScanResult(*outputfile)
	if err != nil {
		fmt.Printf("parse scan result failed, %v.\n", err)
		return
	}

	//err = scandata.SaveResultToPostgre(postgreDb)
	err = scandata.SendResutlToConsole(fmt.Sprintf("%s%s", consoleUrl, ConsoleUrlPath))
	if err != nil {
		fmt.Printf("save host scan result failed, %v.\n", err)
	}

	fmt.Println("write scan result data over!")
}
