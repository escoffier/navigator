package model

import "go.mongodb.org/mongo-driver/bson/primitive"

type CacheEntry struct {
	ID primitive.ObjectID `json:"id" bson:"_id"`
}
