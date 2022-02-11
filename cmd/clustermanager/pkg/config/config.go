package config

type Config struct {
	MasterAddr      string
	Name            string
	APIServerAddr   string
	TLSClient       bool
	CertFile        string
	KeyFile         string
	Port            int
	TLSServer       bool
	WorkerNamespace string
}
