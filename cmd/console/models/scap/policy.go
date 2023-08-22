package scap

import (
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type Policy struct {
	Name    string  `json:"name"`
	Comment string  `json:"comment"`
	RuleIds []int64 `json:"ruleIds"`
}

type PolicyBrief struct {
	ID        uint64          `json:"id"`
	Name      string          `json:"name"`
	Operator  *model.UserLite `json:"operator"`
	CreatedAt int64           `json:"createdAt"`
	UpdatedAt int64           `json:"updatedAt"`
	Comment   string          `json:"comment"`
	IsDefault bool            `json:"isDefault"`
}

type PolicyDetail struct {
	PolicyBrief `json:",inline"`
	Creator     *model.UserLite `json:"creator"`
	Rules       []Rule          `json:"rules"`
}
