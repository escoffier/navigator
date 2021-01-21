package microservice

type ServiceInfoDetails struct {
	Namespace   string   `json:"namespace" bson:"namespace"`
	Name        string   `json:"name" bson:"name"`
	ResName     []string `json:"ResName" bson:"ResName"`
	IsFocus     bool     `json:"isFocus" bson:"isFocus"`
	AliasName   string   `json:"aliasName,omitempty" bson:"aliasName,omitempty"`
	ServiceEdit bool     `json:"serviceEdit,omitempty" bson:"serviceEdit,omitempty"`
	Repository  []string `json:"repository,omitempty" bson:"repository,omitempty"`
}
