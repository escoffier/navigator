package main

import (
	"os"

	"gitlab.com/piccolo_su/vegeta/cmd/clustermanager/cmd"
	_ "go.uber.org/automaxprocs"
)

func main() {
	command := cmd.NewClusterManagerCommand()

	if command.Execute() != nil {
		os.Exit(1)
	}
}

//func init() {
//	logging.SetVerbose()
//}
