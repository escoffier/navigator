//go:generate swag init --parseDependency --parseInternal --parseDepth 1

package main

import (
	"gitlab.com/piccolo_su/vegeta/cmd/security-profiles-manager/cmd"
	_ "gitlab.com/piccolo_su/vegeta/pkg/model"
)

// @title Security Profiles Manager API·
// @version 1.0
// @description This is the Security Profiles Manager

// @BasePath /
func main() {
	cmd.Execute()
}
