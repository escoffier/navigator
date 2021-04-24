package microservice

import (
	"context"
	"fmt"
	"net/http"
	"time"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/mongotools"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MicroService struct {
	mongodb    *mongotools.DatabaseWrapper
	postgresDB *rdbtools.GormWrapper
}

func NewMicroService(
	mongodb *mongotools.DatabaseWrapper,
	postgresDB *rdbtools.GormWrapper,
) *MicroService {
	return &MicroService{
		mongodb:    mongodb,
		postgresDB: postgresDB,
	}
}

func (m *MicroService) GetAllServiceInfo(ctx context.Context, offset, limit int64, username, search string) ([]ServiceInfoDetails, int64, error) {

	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*5)
	defer mongoCtxCancel()
	opt := options.Find().SetProjection(bson.M{"_id": 0, "namespace": 1, "name": 1})
	opt.SetMaxTime(time.Second * 2)

	filter := bson.M{}
	if search != "" {
		filter = bson.M{
			"$or": []bson.M{
				{"name": bson.M{"$regex": search}},
				{"ownerReferenceName": bson.M{"$regex": search}},
			},
		}
	}

	cur, err := m.mongodb.Get().Collection(model.PodServiceRelationCollection.String()).Find(mongoCtx, filter, opt)
	if err != nil {
		NewMongoError(http.StatusInternalServerError,
			fmt.Errorf("couldn't find document: %w", err))
		return nil, 0, err
	}
	defer func() {
		if err := cur.Close(mongoCtx); err != nil {
			logging.GetLogger().Err(err).Msgf("close cursor error: %v", err)
		}
	}()

	svcMap := make(map[string]struct{}, 100)
	serviceSlice := make([]ServiceInfoDetails, 0, 100)
	for cur.Next(mongoCtx) {
		var service model.PodServiceRelation
		err := cur.Decode(&service)
		if err != nil {
			logging.GetLogger().Error().Msgf("decodeError: %v", err)
			continue
		}
		svcName := service.Name
		stype := TypeService
		ownerKind := ""
		if len(svcName) == 0 {
			logging.GetLogger().Error().Msgf("no service name or ownerReferenceName given in data: %+v", service)
			continue
		}

		key := fmt.Sprintf("%s-%s-%s", service.Cluster, service.Namespace, svcName)
		_, ok := svcMap[key]
		if ok {
			continue
		} else {
			svcMap[key] = struct{}{}
		}
		result := ServiceInfoDetails{
			Namespace: service.Namespace,
			Name:      svcName,
			Type:      stype,
			OwnerKind: ownerKind,
		}

		ResNameSlice, err := assets.GetResNameFromServiceRelation(m.mongodb.Get(), service.Namespace, svcName)
		result.ResName = ResNameSlice
		if err != nil {
			logging.GetLogger().Err(err).Msg(fmt.Sprintf("get serive ResName error: %+v", err))
		}

		IsFocus, err := assets.GetFocusFromServiceRelation(m.mongodb.Get(), service.Namespace, svcName, username)
		result.IsFocus = IsFocus
		if err != nil {
			logging.GetLogger().Err(err).Msg(fmt.Sprintf("get serive ResName error: %+v", err))
		}
		serviceSlice = append(serviceSlice, result)
	}

	end := offset + limit
	if int64(len(serviceSlice)) <= offset+limit {
		end = int64(len(serviceSlice))
	}
	return serviceSlice[offset:end], int64(len(serviceSlice)), nil
}

func (m *MicroService) GetMyFocusServiceInfo(ctx context.Context, offset, limit int64, username, search string) ([]ServiceInfoDetails, int64, error) {

	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*10)
	defer mongoCtxCancel()
	opt := options.Find()
	opt.SetMaxTime(time.Second * 10)
	opt.SetSkip(offset)
	opt.SetLimit(limit)
	opt.SetMaxTime(10 * time.Second)

	copt := options.Count()
	copt.SetMaxTime(time.Second * 2)
	filter := bson.M{"focusName": username}
	if search != "" {
		filter = bson.M{
			"focusName": username,
			"name":      bson.M{"$regex": search},
		}
	}
	itemcount, err := m.mongodb.Get().Collection(model.ServiceRelationCollection.String()).CountDocuments(mongoCtx, filter, copt)
	if err != nil {
		return nil, 0, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Could not find count  documents: %w", err))
	}

	cur, err := m.mongodb.Get().Collection(model.ServiceRelationCollection.String()).Find(mongoCtx, filter, opt)
	if err != nil {
		NewMongoError(http.StatusInternalServerError,
			fmt.Errorf("couldn't find document: %w", err))
		return nil, itemcount, err
	}
	serviceClice := make([]ServiceInfoDetails, 0)
	for cur.Next(mongoCtx) {
		var serviceRl model.ServiceRelation
		err := cur.Decode(&serviceRl)
		if err != nil {
			return nil, itemcount, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", err))
		}
		result := ServiceInfoDetails{
			Namespace: serviceRl.Namespace,
			Name:      serviceRl.Name,
		}
		ResNameSlice, err := assets.GetResNameFromServiceRelation(m.mongodb.Get(), serviceRl.Namespace, serviceRl.Name)
		result.ResName = ResNameSlice
		if err != nil {
			logging.GetLogger().Err(err).Msg(fmt.Sprintf("get serive ResName error: %+v", err))
		}
		result.IsFocus = false
		IsFocus, err := assets.GetFocusFromServiceRelation(m.mongodb.Get(), serviceRl.Namespace, serviceRl.Name, username)
		if err != nil {
			logging.GetLogger().Err(err).Msg(fmt.Sprintf("get serive ResName error: %+v", err))
		} else {
			result.IsFocus = IsFocus
		}
		serviceClice = append(serviceClice, result)
	}
	return serviceClice, itemcount, nil
}

func (m *MicroService) SetMyFocusServiceInfo(ctx context.Context, namespace, svcname, username, stype string) error {

	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*10)
	defer mongoCtxCancel()
	filter := bson.M{
		"namespace": namespace,
		"name":      svcname,
		"focusName": username,
	}

	assetServiceRl := model.ServiceRelation{
		Namespace: namespace,
		Name:      svcname,
		FocusName: username,
	}

	if stype == "Focus" {
		update := bson.M{"$set": assetServiceRl}
		opts := options.Update().SetUpsert(true)
		_, err := m.mongodb.Get().Collection(model.ServiceRelationCollection.String()).UpdateOne(mongoCtx, filter, update, opts)
		if err != nil {
			logging.GetLogger().Error().Err(err).Str("asset", fmt.Sprintf("%+v", assetServiceRl)).Msg("Failed to upsert assetServiceRl to mongo")
			return err
		}
		return nil
	} else {
		//not Focus
		_, err := m.mongodb.Get().Collection(model.ServiceRelationCollection.String()).DeleteOne(mongoCtx, filter)
		if err != nil {
			logging.GetLogger().Error().Err(err).Str("asset", fmt.Sprintf("%+v", assetServiceRl)).Msg("Failed to delete  EndPoints to mongo")
			return err
		}
		return nil
	}
}

func (m *MicroService) GetServiceInfo(ctx context.Context, namespace, svcname, username string) ([]ServiceInfoDetails, error) {

	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*10)
	defer mongoCtxCancel()
	opt := options.FindOne().SetProjection(bson.M{"_id": 0, "namespace": 1, "name": 1})
	opt.SetMaxTime(time.Second * 2)

	filter := bson.M{
		"namespace": namespace,
		"name":      svcname,
	}
	var service model.PodServiceRelation

	err := m.mongodb.Get().Collection(model.PodServiceRelationCollection.String()).FindOne(mongoCtx, filter, opt).Decode(&service)
	if err != nil {
		NewMongoError(http.StatusInternalServerError,
			fmt.Errorf("Couldn't find document: %w", err))
		return nil, err
	}

	result := ServiceInfoDetails{
		Namespace: service.Namespace,
		Name:      service.Name,
	}
	ResNameSlice, err := assets.GetResNameFromServiceRelation(m.mongodb.Get(), service.Namespace, service.Name)
	result.ResName = ResNameSlice
	if err != nil {
		logging.GetLogger().Err(err).Msg(fmt.Sprintf("get serive ResName error: %+v", err))
	}

	IsFocus, err := assets.GetFocusFromServiceRelation(m.mongodb.Get(), service.Namespace, service.Name, username)
	result.IsFocus = IsFocus
	if err != nil {
		logging.GetLogger().Err(err).Msg(fmt.Sprintf("get serive ResName error: %+v", err))
	}

	Repository, err := assets.GetServiceRepository(m.mongodb.Get(), namespace, svcname)
	if err != nil {
		return nil, NewMongoError(http.StatusInternalServerError,
			fmt.Errorf("Couldn't get podName from service info : %w", err))
	}
	result.Repository = Repository
	alias, err := assets.GetAliasName(m.mongodb.Get(), namespace, svcname)
	if err != nil {
		logging.GetLogger().Err(err).Msg(fmt.Sprintf("get serive ResNalias name error: %+v", err))
		result.AliasName = ""
	} else {
		result.AliasName = alias
	}

	//service edit
	if username == "admin" || username == "SuperAdmin" {
		result.ServiceEdit = true
	} else {
		result.ServiceEdit = false
		for _, v := range ResNameSlice {
			if v == username {
				result.ServiceEdit = true
				break
			}
		}
	}
	item := make([]ServiceInfoDetails, 0)
	item = append(item, result)

	return item, nil
}

func (m *MicroService) GetUserNameInfo(ctx context.Context, search string) ([]string, error) {

	var user []model.User
	m.postgresDB.Get().Where("name LIKE '%?%'", search).Find(&user)
	nameClice := make([]string, 0)
	for _, v := range user {
		nameClice = append(nameClice, v.UserName)
	}
	return nameClice, nil
}

func (m *MicroService) SetRespServiceInfo(ctx context.Context, namespace, svcname string, respname []string) error {

	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*10)
	defer mongoCtxCancel()

	filter := bson.M{
		"namespace": namespace,
		"name":      svcname,
	}
	opt := options.Find()
	opt.SetMaxTime(2 * time.Second)
	cur, err := m.mongodb.Get().Collection(model.ServiceRelationCollection.String()).Find(mongoCtx, filter, opt)
	if err != nil {
		NewMongoError(http.StatusInternalServerError,
			fmt.Errorf("Couldn't find document: %w", err))
		return err
	}
	for cur.Next(mongoCtx) {
		var serviceRl model.ServiceRelation
		err := cur.Decode(&serviceRl)
		if err != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", err))
		}
		if serviceRl.Namespace != "" && serviceRl.Name != "" && serviceRl.ResName != "" {
			filter = bson.M{
				"namespace": namespace,
				"name":      svcname,
				"resName":   serviceRl.ResName,
			}
			//not Focus
			_, err := m.mongodb.Get().Collection(model.ServiceRelationCollection.String()).DeleteOne(mongoCtx, filter)
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("Failed to delete  EndPoints to mongo")
				return err
			}
		}
	}

	for _, v := range respname {
		filter = bson.M{
			"namespace": namespace,
			"name":      svcname,
			"resName":   v,
		}

		assetServiceRl := model.ServiceRelation{
			Namespace: namespace,
			Name:      svcname,
			ResName:   v,
		}

		update := bson.M{"$set": assetServiceRl}
		opts := options.Update().SetUpsert(true)
		_, err := m.mongodb.Get().Collection(model.ServiceRelationCollection.String()).UpdateOne(mongoCtx, filter, update, opts)
		if err != nil {
			logging.GetLogger().Error().Err(err).Str("asset", fmt.Sprintf("%+v", assetServiceRl)).Msg("Failed to upsert assetServiceRl to mongo")
		}
	}
	return nil
}

func (m *MicroService) SetAliasName(ctx context.Context, namespace, svcname, aliasname string) error {

	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*10)
	defer mongoCtxCancel()
	filter := bson.M{
		"namespace": namespace,
		"name":      svcname,
	}
	_, err := m.mongodb.Get().Collection(model.ServiceAliasCollection.String()).DeleteMany(mongoCtx, filter)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("Failed to delete  EndPoints to mongo")
		return err
	}

	filter = bson.M{
		"namespace": namespace,
		"name":      svcname,
		"AliasName": aliasname,
	}

	assetServiceAlias := model.ServiceAlias{
		Namespace: namespace,
		Name:      svcname,
		AliasName: aliasname,
	}

	update := bson.M{"$set": assetServiceAlias}
	opts := options.Update().SetUpsert(true)
	_, err = m.mongodb.Get().Collection(model.ServiceAliasCollection.String()).UpdateOne(mongoCtx, filter, update, opts)
	if err != nil {
		logging.GetLogger().Error().Err(err).Str("asset", fmt.Sprintf("%+v", assetServiceAlias)).Msg("Failed to upsert assetServiceRl to mongo")
		return err
	}
	return nil
}
