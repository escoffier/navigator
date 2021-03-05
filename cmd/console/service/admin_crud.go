package service

import (
	"context"
	"errors"
	"sync"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func mongoAdminCheck(ctx context.Context, mongodb *mongo.Database) error {
	checkSuperAdmin(ctx, mongodb)
	ok, err := checkRBACCollection(ctx, mongodb)
	if err != nil {
		return err
	}

	if !ok {
		dropRBACCollection(ctx, mongodb)
		return setupRBAC(ctx, mongodb)
	}

	return nil
}

func dropRBACCollection(ctx context.Context, mongodb *mongo.Database) {
	var colls [5]string = [5]string{
		model.UserCollection,
		model.RoleCollection,
		model.AccessCollection,
		model.RelaUserRoleCollection,
		model.RelaRoleAccessCollection,
	}

	wg := sync.WaitGroup{}
	for _, e := range colls {
		wg.Add(1)
		go func(collName string) {
			c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			defer wg.Done()
			mongodb.Collection(collName).Drop(c)
		}(e)
	}
	wg.Wait()
}

// check User and Mod collection whether exist in mongo
func checkRBACCollection(ctx context.Context, mongodb *mongo.Database) (bool, error) {
	// get collections name
	existCollNames, err := mongodb.ListCollectionNames(ctx, bson.M{})
	if err != nil {
		return false, errors.New("checkMongoCollection() -> mongodb.ListCollectionNames() err : " + err.Error())
	}

	var (
		userCollOK       bool
		roleCollOK       bool
		accessCollOK     bool
		relpUserRoleOK   bool
		relpRoleAccessOK bool
	)

	// check collection names match or not
	for _, e := range existCollNames {
		switch e {
		case model.UserCollection:
			userCollOK = true
		case model.RoleCollection:
			roleCollOK = true
		case model.AccessCollection:
			accessCollOK = true
		case model.RelaUserRoleCollection:
			relpUserRoleOK = true
		case model.RelaRoleAccessCollection:
			relpRoleAccessOK = true
		}
	}

	if !(userCollOK && roleCollOK && accessCollOK && relpUserRoleOK && relpRoleAccessOK) {
		return false, nil
	}

	return true, nil
}

func checkSuperAdmin(ctx context.Context, mongodb *mongo.Database) (err error) {
	find := bson.M{
		"user_name": model.DEFAULT_SUPER_ADMIN_USER,
	}
	res := mongodb.Collection(model.UserCollection).FindOne(ctx, find)
	if res.Err() == mongo.ErrNoDocuments {
		superAdmin := model.SuperAdminBson()
		_, err := mongodb.Collection(model.UserCollection).InsertOne(ctx, superAdmin)
		if err != nil {
			return err
		}
		relpSA := model.SuperAdminRela()
		_, err = mongodb.Collection(model.RelaUserRoleCollection).InsertOne(ctx, relpSA)

		return err
	}
	return nil
}

func setupRBAC(ctx context.Context, mongodb *mongo.Database) (err error) {

	// super-admin to user collection
	superAdmin := model.SuperAdminBson()
	_, err11 := mongodb.Collection(model.UserCollection).InsertOne(ctx, superAdmin)
	idxU := model.IdxUserColl()
	_, err12 := mongodb.Collection(model.UserCollection).Indexes().CreateOne(ctx, idxU)

	// role collection
	allRole := model.AllRole()
	_, err21 := mongodb.Collection(model.RoleCollection).InsertMany(ctx, allRole)
	idxR := model.IdxRoleColl()
	_, err22 := mongodb.Collection(model.RoleCollection).Indexes().CreateOne(ctx, idxR)

	// access collection
	allAccess := model.AllAccess()
	_, err31 := mongodb.Collection(model.AccessCollection).InsertMany(ctx, allAccess)
	idxA := model.IdxAccessColl()
	_, err32 := mongodb.Collection(model.AccessCollection).Indexes().CreateOne(ctx, idxA)

	// relation-user-role collection
	relpSA := model.SuperAdminRela()
	_, err41 := mongodb.Collection(model.RelaUserRoleCollection).InsertOne(ctx, relpSA)
	idxUR1, idxUR2 := model.IdxRelaUserRoleColl()
	_, err42 := mongodb.Collection(model.RelaUserRoleCollection).Indexes().CreateOne(ctx, idxUR1)
	_, err43 := mongodb.Collection(model.RelaUserRoleCollection).Indexes().CreateOne(ctx, idxUR2)

	// relation-role-access collection
	defaultRelaRA := model.DefaultRoleAccessRela()
	_, err51 := mongodb.Collection(model.RelaRoleAccessCollection).InsertMany(ctx, defaultRelaRA)
	idxRA1, idxRA2 := model.IdxRelaRoleAccessColl()
	_, err52 := mongodb.Collection(model.RelaUserRoleCollection).Indexes().CreateOne(ctx, idxRA1)
	_, err53 := mongodb.Collection(model.RelaUserRoleCollection).Indexes().CreateOne(ctx, idxRA2)

	err = handleError(
		err11, err12,
		err21, err22,
		err31, err32,
		err41, err42, err43,
		err51, err52, err53,
	)

	return
}

func handleError(errs ...error) error {
	var (
		err error
		ok  bool = true
	)

	for i := range errs {
		if errs[i] != nil {
			logging.GetLogger().Debug().Msg("{super-admin} - " + errs[i].Error())
			ok = false
		}
	}

	if !ok {
		err = errors.New("setup RBAC collection error")
	}

	return err
}
