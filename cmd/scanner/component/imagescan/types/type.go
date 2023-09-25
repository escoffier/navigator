package types

type WebshellSaveInfo struct {
	FileMd5  string `json:"fileMd5"`
	Data     []byte `json:"data"`
	Filename string `json:"filename"`
}
