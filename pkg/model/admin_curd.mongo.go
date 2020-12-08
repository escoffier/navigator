package model

import (
	"context"
	"encoding/json"
	"errors"
	"math/rand"
	"strconv"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func SelectUser(ctx context.Context, mongodb *mongo.Database, userName string) (User, bool, error) {
	filter := NewUserFilter(userName)
	cur, err := mongodb.Collection(UserCollection).Find(ctx, filter)
	if err != nil {
		return User{}, false, errors.New("SelectUser() -> mongodb.Collection().Find() err :" + err.Error())
	}
	defer cur.Close(ctx)

	u := User{}
	if cur.Next(ctx) {
		err := cur.Decode(&u)
		if err != nil {
			return u, false, err
		} else {
			return u, true, nil
		}
	}

	if cur.Err() != nil {
		return u, false, errors.New("SelectUser() -> cur.Err() err :" + cur.Err().Error())
	}

	return u, false, nil

}

func SelectUserAll(ctx context.Context, mongodb *mongo.Database, limit, page int64) ([]User, error) {

	filter := bson.M{}
	ops := options.Find()

	cur, err := mongodb.Collection(UserCollection).Find(ctx, filter,
		ops.SetLimit(limit),
		ops.SetSkip((page-1)*limit))
	if err != nil {
		return nil, errors.New("SelectUserAll() -> mongodb.Collection().Find() err : " + err.Error())
	}
	defer cur.Close(ctx)

	result := make([]User, 0, 30)
	for cur.Next(ctx) {
		u := User{}
		err := cur.Decode(&u)
		if err != nil {
			logging.GetLogger().Debug().Msg("SelectUserAll() - " + err.Error())
			return nil, errors.New("SelectUserAll() -> cur.Decode() err : " + err.Error())
		}
		result = append(result, u)
	}

	if cur.Err() != nil {
		return result, errors.New("SelectUserAll() -> cur.Err() err : " + cur.Err().Error())
	}

	return result, nil
}

func SelectRoleAll(ctx context.Context, mongodb *mongo.Database, limit, page int64) ([]Role, error) {
	filter := bson.M{}
	ops := options.Find()

	cur, err := mongodb.Collection(RoleCollection).Find(ctx, filter,
		ops.SetLimit(limit),
		ops.SetSkip((page-1)*limit))

	if err != nil {
		return nil, errors.New("SelectRoleAll() -> mongodb.Collection().Find() err : " + err.Error())
	}
	defer cur.Close(ctx)

	result := make([]Role, 0, 30)
	for cur.Next(ctx) {
		r := Role{}
		err := cur.Decode(&r)
		if err != nil {
			logging.GetLogger().Debug().Msg("SelectRoleAll() - " + err.Error())
			return nil, errors.New("SelectRoleAll() -> cur.Decode() err : " + err.Error())
		}
		result = append(result, r)
	}

	if cur.Err() != nil {
		return result, errors.New("SelectRoleAll() -> cur.Err() err : " + cur.Err().Error())
	}

	return result, nil
}

func SelectRoleMulti(ctx context.Context, mongodb *mongo.Database, roleNameList []string) ([]Role, error) {
	filter := bson.M{
		"role_name": bson.M{
			"$in": roleNameList,
		},
	}

	cur, err := mongodb.Collection(RoleCollection).Find(ctx, filter)
	if err != nil {
		return nil, errors.New("SelectRoleMulti() -> mongodb.Collection().Find() err : " + err.Error())
	}
	defer cur.Close(ctx)

	result := make([]Role, 0, 30)
	for cur.Next(ctx) {
		r := Role{}
		err := cur.Decode(&r)
		if err != nil {
			logging.GetLogger().Debug().Msg("SelectRoleMulti() - " + err.Error())
			return nil, errors.New("SelectRoleMulti() -> cur.Decode() err : " + err.Error())
		}
		result = append(result, r)
	}

	if cur.Err() != nil {
		return result, errors.New("SelectRoleMulti() -> cur.Err() err : " + cur.Err().Error())
	}

	return result, nil
}

func SelectAccessAll(ctx context.Context, mongodb *mongo.Database, limit, page int64) ([]Access, error) {
	filter := bson.M{}
	ops := options.Find()

	cur, err := mongodb.Collection(AccessCollection).Find(ctx, filter,
		ops.SetLimit(limit),
		ops.SetSkip((page-1)*limit))

	if err != nil {
		return nil, errors.New("SelectAccessAll() -> mongodb.Collection().Find() err : " + err.Error())
	}
	defer cur.Close(ctx)

	result := make([]Access, 0, 30)
	for cur.Next(ctx) {
		a := Access{}
		err := cur.Decode(&a)
		if err != nil {
			logging.GetLogger().Debug().Msg("SelectAccessAll() - " + err.Error())
			return nil, errors.New("SelectAccessAll() -> cur.Decode() err : " + err.Error())
		}

		result = append(result, a)
	}

	if cur.Err() != nil {
		return result, errors.New("SelectAccessAll() -> cur.Err() err : " + cur.Err().Error())
	}

	return result, nil
}

func SelectAccessMulti(ctx context.Context, mongodb *mongo.Database, accessNameList []string) ([]Access, error) {
	filter := bson.M{
		"access_name": bson.M{
			"$in": accessNameList,
		},
	}

	cur, err := mongodb.Collection(AccessCollection).Find(ctx, filter)

	if err != nil {
		return nil, errors.New("SelectAccessMulti() -> mongodb.Collection().Find() err : " + err.Error())
	}
	defer cur.Close(ctx)

	result := make([]Access, 0, 30)
	for cur.Next(ctx) {
		a := Access{}
		err := cur.Decode(&a)
		if err != nil {
			logging.GetLogger().Debug().Msg("SelectAccessMulti() - " + err.Error())
			return nil, errors.New("SelectAccessMulti() -> cur.Decode() err : " + err.Error())
		}
		result = append(result, a)
	}

	if cur.Err() != nil {
		return result, errors.New("SelectAccessMulti() -> cur.Err() err : " + cur.Err().Error())
	}

	return result, nil
}

func InsertUser(ctx context.Context, mongodb *mongo.Database, userName, title string) (ok bool, u User, err error) {

	pwd := randomPwd()

	bs := NewUserBson(userName, pwd, title)
	_, err = mongodb.Collection(UserCollection).InsertOne(ctx, bs)
	if err != nil {
		return false, User{}, errors.New("InsertUser() -> mongodb.Collection().InsertOne() err : " + err.Error())
	}

	ok = true
	u = User{
		UserName: userName,
		Pwd:      pwd,
		Title:    title,
	}
	return
}

func InsertRelaUserRole(ctx context.Context, mongodb *mongo.Database,
	userName, roleName string) (bool, error) {
	rela := NewRelationUserRole(userName, roleName)

	_, err := mongodb.Collection(RelaUserRoleCollection).InsertOne(ctx, rela)
	if err != nil {
		return false, errors.New("InsertRelaUserRole() -> mongodb.Collection().InsertOne() err : " + err.Error())
	}

	return true, nil
}

func SelectRelaUserRole(ctx context.Context, mongodb *mongo.Database,
	userName, roleName string) ([]RelaUserRole, []string, error) {

	var filter bson.M

	if userName == "" {
		filter = bson.M{
			"role_name": roleName,
		}
	} else if roleName == "" {
		filter = bson.M{
			"user_name": userName,
		}
	} else if userName == "" && roleName == "" {
		return nil, nil, errors.New("SelectRelaUserRole() err : param not found")
	} else {
		filter = bson.M{
			"role_name": roleName,
			"user_name": userName,
		}
	}

	result := make([]RelaUserRole, 0, 20)
	resultNames := make([]string, 0, 20)

	cur, err := mongodb.Collection(RelaUserRoleCollection).Find(ctx, filter) //.Decode(&rela)
	if err != nil {
		return nil, nil, errors.New("SelectRelaUserRole() -> mongodb.Collection().Find() err : " + err.Error())
	}

	defer cur.Close(ctx)
	for cur.Next(ctx) {
		rela := RelaUserRole{}
		if err := cur.Decode(&rela); err != nil {
			logging.GetLogger().Debug().Msg("SelectRelaUserRole() - " + err.Error())
			return nil, nil, errors.New("SelectRelaUserRole() -> cur.Decode() err : " + err.Error())
		}
		result = append(result, rela)
		resultNames = append(resultNames, rela.RoleName)
	}

	if cur.Err() != nil {
		return result, resultNames, errors.New("SelectRelaUserRole() -> cur.Err() err : " + cur.Err().Error())
	}

	return result, resultNames, err
}

func UpdateRelaUserRole(ctx context.Context, mongodb *mongo.Database, userName, roleName string) (int64, error) {
	filter := bson.M{
		"user_name": bson.M{
			"$eq": userName,
		},
	}
	update := bson.M{
		"$set": bson.M{
			IdxRelaUR_2: roleName,
		},
	}

	updateResult, err := mongodb.Collection(RelaUserRoleCollection).UpdateOne(ctx, filter, update)

	if err != nil {
		return 0, errors.New("UpdateRelaUserRole() -> mongodb.Collection().UpdateOne() err : " + err.Error())
	}
	return updateResult.UpsertedCount, nil
}

func SelectRelaRoleAccess(ctx context.Context, mongodb *mongo.Database,
	roleName, accessName string) ([]RelaRoleAcs, []string, error) {
	var filter bson.M

	if roleName == "" {
		filter = bson.M{
			"access_name": accessName,
		}
	} else if accessName == "" {
		filter = bson.M{
			"role_name": roleName,
		}
	} else {
		filter = bson.M{
			"role_name":   roleName,
			"access_name": accessName,
		}
	}

	result := make([]RelaRoleAcs, 0, 20)
	accessNames := make([]string, 0, 20)

	cur, err := mongodb.Collection(RelaRoleAccessCollection).Find(ctx, filter)
	if err != nil {
		return nil, nil, errors.New("SelectRelaRoleAccess() -> mongodb.Collection().Find() err : " + err.Error())
	}
	defer cur.Close(ctx)
	for cur.Next(ctx) {
		rela := RelaRoleAcs{}
		err := cur.Decode(&rela)
		if err != nil {
			logging.GetLogger().Debug().Msg("SelectRelaRoleAccess() - " + err.Error())
			return nil, nil, errors.New("SelectRelaRoleAccess() -> cur.Decode() err : " + err.Error())
		}
		result = append(result, rela)
		accessNames = append(accessNames, rela.AccessName)
	}

	if cur.Err() != nil {
		return result, accessNames, errors.New("SelectRelaRoleAccess() -> cur.Err() err : " + cur.Err().Error())
	}

	return result, accessNames, nil
}

func InsertRelaRoleAccess(ctx context.Context, mongodb *mongo.Database,
	roleName, accessName string) (bool, error) {
	rela := NewRelationRoleAccess(roleName, accessName)

	_, err := mongodb.Collection(RelaRoleAccessCollection).InsertOne(ctx, rela)
	if err != nil {
		return false, errors.New("InsertRelaRoleAccess() -> mongodb.Collection().InsertOne() err : " + err.Error())
	}

	return true, nil
}

func DeleteRelaRoleAccess(ctx context.Context, mongodb *mongo.Database,
	roleName, accessName string) (bool, error) {
	rela := NewRelationRoleAccess(roleName, accessName)

	_, err := mongodb.Collection(RelaRoleAccessCollection).DeleteOne(ctx, rela)
	if err != nil {
		return false, errors.New("DeleteRelaRoleAccess() -> mongodb.Collection().InsertOne() err : " + err.Error())
	}
	return true, nil
}

func randomPwd() string {
	rand.Seed(time.Now().Unix())
	result := int(0)

	for bitCount := 0; bitCount < 6; bitCount++ {
		n := rand.Intn(10)
		result = result*10 + n
	}

	return strconv.Itoa(result)
}

func testWithLogJson(middle string, payload interface{}) {
	pre := "{super-admin} -> "
	middle = middle + " -> "
	jso, err := json.Marshal(payload)
	if err != nil {
		logging.GetLogger().Debug().Msg(pre + middle + " json err:" + err.Error())
	} else {
		logging.GetLogger().Debug().Msg(pre + middle + string(jso))
	}

}
