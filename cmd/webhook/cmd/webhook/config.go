package webhook

type Config struct {
	CertFile            string
	KeyFile             string
	Port                int
	ImageValidateServer string
	IgnoredNameSpaces   []string
	Validators          []string
	Mutators            []string
	Timeout             int32
	Concurrency         int32
}
