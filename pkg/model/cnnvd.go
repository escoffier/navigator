package model

import "go.mongodb.org/mongo-driver/bson/primitive"

type Cve2cnnvdMapping struct {
	MetadataEntry `json:"-" bson:",inline"`
	ID            primitive.ObjectID `json:"db_id,omitempty" bson:"_id,omitempty"`
	CVE           string             `json:"cve" bson:"cve"`
	CVNND         string             `json:"cvnnd" bson:"cvnnd"`
	CVNNDLink     string             `json:"cvnndLink" bson:"cvnndLink"`
	UpdatedAt     int64              `json:"updatedAt" bson:"updatedAt"`
}
