package outputter

import (
	"encoding/json"

	"gopkg.in/yaml.v2"
)

// Format of the output
type Format int

const (
	// DefaultFormat is json output
	DefaultFormat Format = iota
	JSONFormat
	YAMLFormat
)

type Formater interface {
	Serialize(data interface{}) ([]byte, error)
}

func (f Format) Serialize(data interface{}) ([]byte, error) {
	switch f {
	case YAMLFormat:
		return yaml.Marshal(data)
	case JSONFormat:
		fallthrough
	default:
		return json.Marshal(data)
	}
}

// Outputter represents the output strategy for Control objects
type Outputter interface {
	Output(format Formater, data interface{}) error
}

type ScanResult struct {
	CheckType  string      `json:"checkType"`
	TaskID     string      `json:"taskID"`
	Hostname   string      `json:"hostname"`
	ClusterKey string      `json:"clusterKey"`
	Payload    interface{} `json:"payload"`
}
