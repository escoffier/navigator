package model

type SeccompProfileAlertRequest struct {
	PodUID      string `json:"poduid"`
	Podname     string `json:"podname"`
	ProfileName string `json:"profileName"`
	ContainerID string `json:"containerID"`
	Phase       string `json:"phase"`
	Action      string `json:"action"`
	Syscall     string `json:"syscall"`
}
