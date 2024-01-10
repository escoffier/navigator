package waf

import v1alpha1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/waf.security.io/v1alpha1"

type StringMatch struct {
	Prefix string `json:"prefix,omitempty"`
	Exact  string `json:"exact,omitempty"`
}

type MatchExpression struct {
	ID     uint32 `json:"id,omitempty"`
	Name   string `json:"name,omitempty"`
	Mode   string `json:"mode,omitempty"`
	Scope  string `json:"scope,omitempty"`
	Expr   string `json:"expr,omitempty"`
	Status int32  `json:"status,omitempty"`
}

type LogConfig struct {
	Enable int    `json:"attack_enable,omitempty"`
	Level  string `json:"level,omitempty"`
}

type Rule struct {
	ID          int
	Level       int
	Name        string
	Type        string
	Description string
	Expr        string
	Mode        string
}

type EventPostConf struct {
	Address  string
	Interval int32
}

type Config struct {
	UUID              string                     `json:"uuid"`
	MsgType           int                        `json:"msg_type"`
	PodIPs            []string                   `json:"pod_ips"`
	Mode              string                     `json:"mode"`
	ClusterKey        string                     `json:"cluster_key"`
	Namespace         string                     `json:"namespace"`
	Kind              string                     `json:"kind"`
	WorkLoadName      string                     `json:"workload_name"`
	Name              string                     `json:"name"`
	ServiceID         uint32                     `json:"service_id"`
	Log               LogConfig                  `json:"log"`
	Rules             []Rule                     `json:"rules"`
	BlackWhireLists   []v1alpha1.MatchExpression `json:"black_white_lists"`
	ExcludedFileTypes []string                   `json:"excluded_file_types"`
	DetectHeaders     []string                   `json:"detect_headers"`
	Domain            []string                   `json:"domain"`
	Uri               string                     `json:"uri"`
	Post              EventPostConf              `json:"post"`
}
