package scap

import (
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type RecordDetail struct {
	CheckID     string          `json:"checkId" bson:"checkId"`
	CheckType   string          `json:"checkType" bson:"checkType"`
	ClusterID   string          `json:"clusterId" bson:"clusterId"`
	Operator    *model.UserLite `json:"operator" bson:"operator"`
	ClusterName string          `json:"clusterName" bson:"-"`
	CreatedAt   int64           `json:"createdAt" bson:"createdAt"`
	FinishedAt  int64           `json:"finishedAt,omitempty" bson:"finishedAt,omitempty"`
	PolicyID    uint            `json:"policyId" bson:"policyId"`
	PolicyName  string          `json:"policyName" bson:"policyName"`
	State       model.ScanState `json:"state" bson:"state"`
}
