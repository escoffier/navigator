package mongotools

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

const (
	MongoURL               = "mongodb://admin:admin@localhost:27017"
	MongoTimeout           = time.Duration(10 * time.Second)
	MongoHeartbeatInterval = time.Duration(100 * time.Microsecond)
)

type MongoOperator string

func (o MongoOperator) String() string {
	return string(o)
}

const (
	Equal         MongoOperator = "$eq"
	GT            MongoOperator = "$gt"
	GTE           MongoOperator = "$gte"
	LT            MongoOperator = "$lt"
	LTE           MongoOperator = "$lte"
	NotEqual      MongoOperator = "$ne"
	IN            MongoOperator = "$in"
	NotIn         MongoOperator = "$nin"
	Or            MongoOperator = "$or"
	And           MongoOperator = "$and"
	Not           MongoOperator = "not"
	Nor           MongoOperator = "nor"
	Exists        MongoOperator = "$exists"
	Type          MongoOperator = "type"
	Coordinates   MongoOperator = "coordinates"
	Mod           MongoOperator = "mod"
	Like          MongoOperator = "$regex"
	Text          MongoOperator = "text"
	Where         MongoOperator = "where"
	GeoWithIn     MongoOperator = "geoWithin"
	GeoIntersects MongoOperator = "geoIntersects"
	Near          MongoOperator = "near"
	NearSphere    MongoOperator = "nearSphere"
	All           MongoOperator = "all"
	ElemMatch     MongoOperator = "$elemMatch"
	Size          MongoOperator = "$size"
	Sum           MongoOperator = "$sum"
	AddToSet      MongoOperator = "$addToSet"
	Set           MongoOperator = "$set"
	UnSet         MongoOperator = "$unset"
	Inc           MongoOperator = "$inc"
	SetIsSubset   MongoOperator = "$setIsSubset"
	Filter        MongoOperator = "$filter"
	Last          MongoOperator = "$last"
	First         MongoOperator = "$first"
	Cond          MongoOperator = "$cond"
	Avg           MongoOperator = "$avg"

	Match   MongoOperator = "$match"
	Project MongoOperator = "$project"
	Unwind  MongoOperator = "$unwind"
	Group   MongoOperator = "$group"
	Limit   MongoOperator = "$limit"
	Skip    MongoOperator = "$skip"
	Sort    MongoOperator = "$sort"
	Lookup  MongoOperator = "$lookup"
	GeoNear MongoOperator = "$geoNear"

	DateToStringOper MongoOperator = "$dateToString"
	DayOfMonthOper   MongoOperator = "$dayOfMonth"
	Concat           MongoOperator = "$concat"
	Substr           MongoOperator = "$substr"

	Literal MongoOperator = "$literal"
	Each    MongoOperator = "$each"
	PullAll MongoOperator = "$pullAll"
	Push    MongoOperator = "$push"
	Update  MongoOperator = "$update"
)

func GenProjection(fields []string) map[string]int {
	pro := make(map[string]int)
	for _, v := range fields {
		pro[v] = 1
	}
	return pro
}

func GenObjectId(ids []string) []primitive.ObjectID {
	res := make([]primitive.ObjectID, 0)
	for _, id := range ids {
		if oid, err := primitive.ObjectIDFromHex(id); err == nil {
			res = append(res, oid)
		}
	}
	return res
}
