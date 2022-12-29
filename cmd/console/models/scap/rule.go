package scap

import "gitlab.com/piccolo_su/vegeta/pkg/model"

type Rule struct {
	ID             uint                               `json:"id"`
	RawID          string                             `json:"rawId"`
	Title          string                             `json:"title"`
	Detail         string                             `json:"detail"`
	Remediation    string                             `json:"remediation"`
	ExpectedResult string                             `json:"expectedResult"`
	Audit          string                             `json:"audit"`
	Classified     string                             `json:"classified"`
	ExtraDetail    *model.PolicyDetailInfoExtraDetail `json:"extraDetail,omitempty"`
}
