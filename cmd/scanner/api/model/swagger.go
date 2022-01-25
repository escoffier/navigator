package apimodel

import (
	"gitlab.com/piccolo_su/vegeta/pkg/harbor"
)

type ScanStatusRes struct {
	ScanAllStatus harbor.ScanAllStatus `json:"harborStatus"`
	IsAborted     bool                 `json:"isAborted"` // if true, we are currently in the process of aborting harbor scan all job. Abort button should be disabled.
}
type OnlyFlagRes struct {
	Flag bool `json:"flag"`
}

type OnlyIDRes struct {
	ID int `json:"id"`
}

type OnlyStatusRes struct {
	Status string `json:"status"`
}

type OnlyAccountRes struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type ApiItem struct { // nolint
	Item interface{} `json:"item"`
}

type ApiItems struct { // nolint
	Items interface{} `json:"items"`
}

type ApiWithItem struct { // nolint
	ApiVersion string      `json:"apiVersion"` // nolint
	Data       interface{} `json:"data"`
}
type IDList struct {
}
