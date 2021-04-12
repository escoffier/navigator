package model

import "time"

type AccessLog struct {
	Username   string              `json:"username"`
	RemoteAddr string              `json:"remote_addr"`
	Host       string              `json:"host"`
	Method     string              `json:"method"`
	RequestURI string              `json:"request_uri"`
	Header     map[string][]string `json:"header"`
	Body       string              `json:"body"`
	Time       time.Time           `json:"@timestamp"`
}
