package scap

import "gitlab.com/piccolo_su/vegeta/cmd/console/models"

type Policy struct {
	Name    string  `json:"name"`
	Comment string  `json:"comment"`
	RuleIds []int64 `json:"ruleIds"`
}

type PolicyBrief struct {
	ID        uint   `json:"id"`
	Name      string `json:"name"`
	Operator  string `json:"operator"`
	CreatedAt int64  `json:"createdAt"`
	Comment   string `json:"comment"`
	IsDefault bool   `json:"isDefault"`
}

type PolicyDetail struct {
	PolicyBrief `json:",inline"`
	Rules       []Rule `json:"rules"`
}

type CreatePolicyResp struct {
	models.ID `json:",inline"`
}

type UpdatePolicyResp struct {
	models.ID `json:",inline"`
}
