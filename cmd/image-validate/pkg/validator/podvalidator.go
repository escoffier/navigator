package validator

import (
	v1 "k8s.io/api/core/v1"
	"strings"
)

var ApiPath = "/api/v1/imagereject/online_moniter"

type PodValidator struct {
	validatorUrl string
}

func NewPodValidator(url string) *PodValidator {
	if strings.Contains(url, "http") {
		return &PodValidator{validatorUrl: url + ApiPath}
	} else {
		url = "http://" + url + ApiPath
		return &PodValidator{validatorUrl: url}
	}
}

func (v *PodValidator) Validate(pod *v1.Pod) error {
	return v.ValidateImage(pod)
}
