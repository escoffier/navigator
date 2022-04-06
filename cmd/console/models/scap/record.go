package scap

type RecordDetail struct {
	CheckID     string `json:"checkId" bson:"checkId"`
	CheckType   string `json:"checkType" bson:"checkType"`
	ClusterID   string `json:"clusterId" bson:"clusterId"`
	Operator    string `json:"operator" bson:"operator"`
	ClusterName string `json:"clusterName" bson:"-"`
	CreatedAt   int64  `json:"createdAt" bson:"createdAt"`
	FinishedAt  int64  `json:"finishedAt,omitempty" bson:"finishedAt,omitempty"`
	PolicyID    uint   `json:"policyId" bson:"policyId"`
	PolicyName  string `json:"policyName" bson:"policyName"`
	// 1.运行中 2.完成 3.失败
	State uint8 `json:"state" bson:"state"`
}
