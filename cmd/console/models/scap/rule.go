package scap

type Rule struct {
	ID             uint   `json:"id"`
	RawID          string `json:"rawId"`
	TitleEn        string `json:"titleEn"`
	TitleZh        string `json:"titleZh"`
	DetailEn       string `json:"detailEn"`
	DetailZh       string `json:"detailZh"`
	RemediationEn  string `json:"remediationEn"`
	RemediationZh  string `json:"remediationZh"`
	ExpectedResult string `json:"expectedResult"`
	Audit          string `json:"audit"`
	ClassifiedZh   string `json:"classifiedZh"`
	ClassifiedEn   string `json:"classifiedEn"`
}
