package audit

import (
	"context"
	"fmt"
	"net/http"
	"time"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/repository"

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
	filter := bson.M{"deleted_at": bson.M{"$exists": false}}

	queryResult := s.mongodb.Collection(model.AuditCollection.String()).FindOne(ctx, filter)
	if queryResult.Err() != nil {
		if queryResult.Err() == mongo.ErrNoDocuments {
			return nil, NewAuditConfigDoesntExistError(http.StatusNotFound, fmt.Errorf("Document not found: %w", queryResult.Err()))
		}
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get document: %w", queryResult.Err()))
	}

	err := queryResult.Decode(&queryAuditConfig)
	if err != nil {
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", err))
	}
	return &queryAuditConfig, nil
}

func (s *AuditService) AddAuditConfig(ctx context.Context, auditConfig *model.AuditConfig) (*model.AuditConfig, error) {
	filter := bson.M{"deleted_at": bson.M{"$exists": false}}

	err := s.mongodb.Client().UseSession(ctx, func(sessionContext mongo.SessionContext) error {
		sessionError := sessionContext.StartTransaction()
		if sessionError != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't start transaction: %w", sessionError))
		}

		defer repository.MongoSessionCommitter(sessionContext, &sessionError)()

		queryResult := s.mongodb.Collection(model.AuditCollection.String()).FindOne(sessionContext, filter)
		if queryResult.Err() != nil {
			sessionError = queryResult.Err()
			if sessionError != mongo.ErrNoDocuments {
				return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get document: %w", sessionError))
			}
		} else {
			sessionError = fmt.Errorf("Document already exists")
			return NewMongoError(http.StatusNotFound, sessionError)
		}

		// err = mongo.ErrNoDocuments

		auditConfig.CreatedAt = time.Now()

		_, sessionError = s.mongodb.Collection(model.AuditCollection.String()).InsertOne(sessionContext, auditConfig)
		if sessionError != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't insert document: %w", sessionError))
		}

		return nil
	})
	if err != nil {
		return nil, err
	}
	return auditConfig, nil
}

func (s *AuditService) UpdateAuditConfig(ctx context.Context, upAuditConfig *model.AuditConfig) (*model.AuditConfig, error) {
	filter := bson.M{"deleted_at": bson.M{"$exists": false}}

	upAuditConfig.CreatedAt = time.Now()

	if upAuditConfig.ColdStorageDays <= 0 {
		return nil, NewAuditConfigError(http.StatusBadRequest, fmt.Errorf("Both cold and hot storage expiration date need to be passed"))
	}

	err := s.mongodb.Client().UseSession(ctx, func(sessionContext mongo.SessionContext) error {
		sessionError := sessionContext.StartTransaction()
		if sessionError != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't start transaction: %w", sessionError))
		}

		defer repository.MongoSessionCommitter(sessionContext, &sessionError)()

		queryResult := s.mongodb.Collection(model.AuditCollection.String()).FindOne(sessionContext, filter)
		if queryResult.Err() != nil {
			sessionError = queryResult.Err()
			if sessionError == mongo.ErrNoDocuments {
				return NewMongoError(http.StatusNotFound, fmt.Errorf("Document not found: %w", sessionError))
			}
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get document: %w", sessionError))
		}
		var oldAuditConfig model.AuditConfig
		sessionError = queryResult.Decode(&oldAuditConfig)
		if sessionError != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", sessionError))
		}
		oldAuditConfig.DeletedAt = time.Now()
		oldAuditConfig.HistoricisedTimestamp = time.Now()
		update := bson.M{"$set": oldAuditConfig}

		_, sessionError = s.mongodb.Collection(model.AuditCollection.String()).UpdateOne(sessionContext, filter, update)
		if sessionError != nil {
			if sessionError == mongo.ErrNoDocuments {
				return NewMongoError(http.StatusNotFound, fmt.Errorf("Document not found: %w", sessionError))
			}
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't update document: %w", sessionError))
		}

		_, sessionError = s.mongodb.Collection(model.AuditCollection.String()).InsertOne(sessionContext, upAuditConfig)
		if sessionError != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't insert document: %w", sessionError))
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return upAuditConfig, nil
}
