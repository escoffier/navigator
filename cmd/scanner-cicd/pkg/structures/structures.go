package structures

type ScanOneCICDResultRequest struct {
	ImageID int64  `json:"id"`
	Library string `json:"library"`
}
type AccountRes struct {
	UserName string `json:"username"`
	PassWord string `json:"password"`
}
type AccountData struct {
	Items []AccountRes `json:"items"`
}
type AccountInfo struct {
	APIVersion string      `json:"apiVersion"`
	Data       AccountData `json:"data"`
}

type ScanOneForCICDResponse struct {
	IsScan bool `json:"is_scan"`
	Safe   bool `json:"safe"`

	RejectMsg [][]string `json:"reject_msg"`
	Vulu      [][]string `json:"vulu"`
	Sensitive [][]string `json:"sensitive"`
	Virus     [][]string `json:"virus"`
	Webshell  [][]string `json:"webshell"`
	Envs      [][]string `json:"envs"`
}

type resdata struct {
	Item ScanOneCICDResultRequest `json:"item"`
}

type resultData struct {
	Item ScanOneForCICDResponse `json:"item"`
}

type ResJSON struct {
	APIVersion string  `json:"apiVersion"`
	Data       resdata `json:"data"`
}
type ResultInfo struct {
	APIVersion string     `json:"apiVersion"`
	Data       resultData `json:"data"`
}
type JSONData struct {
	Image     string `json:"image"`
	MaxSecond string `json:"max_second"`
	Library   string `json:"library"`
	Insecure  bool   `json:"insecure"`
}
