//go:generate swag init

package main

import (
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/cmd"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func main() {
	util.InitPprofMontitor()

	cmd.Execute()
}
