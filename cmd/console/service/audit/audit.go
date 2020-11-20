package audit

import (
	"context"
	"fmt"
	"net/http"
	"time"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/model"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type AuditService struct {
	mongodb *mongo.Database
}

func NewAuditService(
	mongodb *mongo.Database,
) *AuditService {
	return &AuditService{
		mongodb: mongodb,
	}
}

func (s *AuditService) GetAuditConfig(ctx context.Context) (*model.AuditConfig, error) {
	var queryAuditConfig model.AuditConfig
	filter := bson.M{"active": true}

	queryResult := s.mongodb.Collection(model.AuditConfigCollection).FindOne(ctx, filter)
	if queryResult.Err() != nil {
		if queryResult.Err() == mongo.ErrNoDocuments {
			return nil, NewMongoError(http.StatusNotFound, fmt.Errorf("Document not found: %w", queryResult.Err()))
		}
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get document: %w", queryResult.Err()))
	}

	err := queryResult.Decode(&queryAuditConfig)
	if err != nil {
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", queryResult.Err()))
	}
	return &queryAuditConfig, nil
}

func (s *AuditService) AddAuditConfig(ctx context.Context, auditConfig *model.AuditConfig) (*model.AuditConfig, error) {
	filter := bson.M{"active": true}

	queryResult := s.mongodb.Collection(model.AuditConfigCollection).FindOne(ctx, filter)
	if queryResult.Err() != nil {
		if queryResult.Err() != mongo.ErrNoDocuments {
			return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get document: %w", queryResult.Err()))
		}
	} else {
		return nil, NewMongoError(http.StatusNotFound, fmt.Errorf("Document already exists"))
	}

	// err = mongo.ErrNoDocuments

	auditConfig.CreatedAt = time.Now()
	auditConfig.Active = true

	_, err := s.mongodb.Collection(model.AuditConfigCollection).InsertOne(ctx, auditConfig)
	if err != nil {
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't insert document: %w", err))
	}

	queryResult = s.mongodb.Collection(model.AuditConfigCollection).FindOne(ctx, filter)
	if queryResult.Err() != nil {
		if queryResult.Err() == mongo.ErrNoDocuments {
			return nil, NewMongoError(http.StatusNotFound, fmt.Errorf("Document not found: %w", queryResult.Err()))
		}
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get document: %w", queryResult.Err()))
	}

	var newAuditConfig model.AuditConfig
	err = queryResult.Decode(&newAuditConfig)
	if err != nil {
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", queryResult.Err()))
	}

	return &newAuditConfig, nil
}

func (s *AuditService) UpdateAuditConfig(ctx context.Context, upAuditConfig *model.AuditConfig) (*model.AuditConfig, error) {
	filter := bson.M{"active": true}

	upAuditConfig.Active = true
	upAuditConfig.CreatedAt = time.Now()

	if upAuditConfig.ColdStorageDays <= 0 {
		return nil, NewAuditConfigError(http.StatusBadRequest, fmt.Errorf("Both cold and hot storage expiration date need to be passed"))
	}

	queryResult := s.mongodb.Collection(model.AuditConfigCollection).FindOne(ctx, filter)
	if queryResult.Err() != nil {
		if queryResult.Err() == mongo.ErrNoDocuments {
			return nil, NewMongoError(http.StatusNotFound, fmt.Errorf("Document not found: %w", queryResult.Err()))
		}
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get document: %w", queryResult.Err()))
	}

	var oldAuditConfig model.AuditConfig
	err := queryResult.Decode(&oldAuditConfig)
	if err != nil {
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", queryResult.Err()))
	}
	oldAuditConfig.Active = false
	oldAuditConfig.DeletedAt = time.Now()
	oldAuditConfig.AuditTimestamp = time.Now()
	update := bson.M{"$set": oldAuditConfig}

	_, err = s.mongodb.Collection(model.AuditConfigCollection).UpdateOne(ctx, filter, update)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, NewMongoError(http.StatusNotFound, fmt.Errorf("Document not found: %w", err))
		}
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't update document: %w", err))
	}

	_, err = s.mongodb.Collection(model.AuditConfigCollection).InsertOne(ctx, upAuditConfig)
	if err != nil {
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't insert document: %w", err))
	}

	queryResult = s.mongodb.Collection(model.AuditConfigCollection).FindOne(ctx, filter)
	if queryResult.Err() != nil {
		if queryResult.Err() == mongo.ErrNoDocuments {
			return nil, NewMongoError(http.StatusNotFound, fmt.Errorf("Document not found: %w", queryResult.Err()))
		}
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get document: %w", queryResult.Err()))
	}

	var auditConfig model.AuditConfig
	err = queryResult.Decode(&auditConfig)
	if err != nil {
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", queryResult.Err()))
	}

	return &auditConfig, nil
}
