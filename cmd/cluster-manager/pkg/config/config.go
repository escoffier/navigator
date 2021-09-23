package config

type Config struct {
	MasterAddr      string
	Name            string
	ApiServerAddr   string
	TlsClient       bool
	CertFile        string
	KeyFile         string
	Port            int
	TlsServer       bool
	WorkerNamespace string
}
