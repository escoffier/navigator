package api

import "gitlab.com/piccolo_su/vegeta/pkg/harbor"

type ScanStatusRes struct {
	ScanAllStatus harbor.ScanAllStatus `json:"harborStatus"`
	IsAborted     bool                 `json:"isAborted"` // if true, we are currently in the process of aborting harbor scan all job. Abort button should be disabled.
}
type OnlyFlagRes struct {
	Flag bool `json:"flag"`
}

type OnlyIdRes struct {
	Id int `json:"id"`
}

type OnlyStatusRes struct {
	Status string `json:"status"`
}

type OnlyAccountRes struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type ApiItem struct {
	Item interface{} `json:"item"`
}

type ApiItems struct {
	Items interface{} `json:"items"`
}

type ApiWithItem struct {
	ApiVersion string      `json:"apiVersion"`
	Data       interface{} `json:"data"`
}
