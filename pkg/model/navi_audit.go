package model

type HttpRequest struct {
	RequestID  string
	RequestURL string
	Method     string
	Path       string
	Proto      string
	RemoteIP   string
	Body       string
}

type HttpResponse struct {
	Bytes   int
	Body    string
	Elapsed float64
	Status  int
	Header  map[string]string
}

type UserInfo struct {
	Name string
	ID   string
}

type NaviAuditEvent struct {
	RequestID    string
	Verb         string
	Detail       string
	User         *UserInfo
	HttpRequest  *HttpRequest
	HttpResponse *HttpResponse
	Timestamp    int64
	MetaData     map[string]interface{}
}
