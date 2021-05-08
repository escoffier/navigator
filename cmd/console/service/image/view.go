package image

type OverView struct {
	ImageTotal  int      `json:"image_total"`
	OnlineTotal int      `json:"online_total"`
	Sum         SafeOver `json:"sum"`
	Online      SafeOver `json:"online"`
}

type SafeOver struct {
	VULN         int `json:"vuln"`
	VIRUS        int `json:"virus"`
	SENSITIVE    int `json:"sensitive"`
	NETWORK_VULN int `json:"network_vuln"`
}
