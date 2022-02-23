package config

import "gitlab.com/piccolo_su/vegeta/pkg/k8s"

type Config struct {
	MasterAddr           string
	Name                 string
	APIServerAddr        string
	TLSClient            bool
	CertFile             string
	KeyFile              string
	Port                 int
	TLSServer            bool
	WorkerNamespace      string
	K8SInfoForRestConfig *k8s.K8SInfoForRestConfig
}
