package types

type SafeFileToKafka struct {
	FileMd5  string `json:"fileMd5"`
	Data     []byte `json:"data"`
	Filename string `json:"filename"`
}

type EtcPasswdUser struct {
	Username string
	Password string
	UID      int64
	GID      string
	Comment  string
	HomeDir  string
	Shell    string
}

type EtcGroupUser struct {
	Name     string
	Password string
	GID      int64
	Members  []string
}
