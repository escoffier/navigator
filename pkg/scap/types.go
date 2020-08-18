package scap

import (
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

//Checker Scap Checker interface
type Checker interface {
	InitializeChecker(*model.ScapTask) error // Initialize the Checker
	Check() (interface{}, error)             // Start a scap check task
	//Wait() ScannerStatus                                       // Wait until task done
	//GetStatus() ScannerStatus                                  // Get scanner status
}

//const (
//	Debian ScannerType = iota
//	Ubuntu
//	CentOS
//)
