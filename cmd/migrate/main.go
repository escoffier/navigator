//go:generate swag init

package main

import (
	"gitlab.com/piccolo_su/vegeta/cmd/migrate/cmd"
)

func main() {
	cmd.Execute()
}
