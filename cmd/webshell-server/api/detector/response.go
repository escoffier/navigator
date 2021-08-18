package detector

type FileResp struct {
	Score int      `json:"score"`
	Codes []string `json:"codes"`
}
