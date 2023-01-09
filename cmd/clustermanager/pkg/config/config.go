package config

import (
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type Config struct {
	MasterAddr            string
	MasterGrpcAddr        string
	Name                  string
	APIServerAddr         string
	ExternalAPIServerAddr string
	ClusterType           model.ClusterType
	TLSClient             bool
	CertFile              string
	KeyFile               string
	Port                  int
	TLSServer             bool
	WorkerNamespace       string
	DBLogDebug            bool
	PoolInfo              *assets.PoolInfo
	Profile               bool
}
