package main

import (
	"gitlab.com/piccolo_su/vegeta/cmd/monitor/cmd"
	_ "go.uber.org/automaxprocs"
	"os"
)

func main() {
	command := cmd.NewMonitorMetricsCommand()
	if command.Execute() != nil {
		os.Exit(1)
	}
}
