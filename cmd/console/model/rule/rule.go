package rule

import "go.mongodb.org/mongo-driver/bson/primitive"

type Rule struct {
	ID          primitive.ObjectID `json:"id" bson:"_id, omitempty"`
	Description string             `json:"description"`
	Name        string             `json:"name"`
	Enabled     bool               `json:"enabled"`
}
