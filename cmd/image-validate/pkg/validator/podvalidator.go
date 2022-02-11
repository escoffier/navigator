package validator

import (
	"strings"

	v1 "k8s.io/api/core/v1"
)

var APIPath = "/api/v1/imagereject/online_moniter"

type PodValidator struct {
	validatorURL string
}

func NewPodValidator(url string) *PodValidator {
	if strings.Contains(url, "http") {
		return &PodValidator{validatorURL: url + APIPath}
	}
	url = "http://" + url + APIPath
	return &PodValidator{validatorURL: url}
}

func (v *PodValidator) Validate(pod *v1.Pod) error {
	return v.ValidateImage(pod)
}
