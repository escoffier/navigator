package rule

import (
	"context"
	"fmt"
	"net/http"
	"time"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/repository"
	"go.mongodb.org/mongo-driver/mongo/options"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type RuleService struct {
	mongodb                  *mongo.Database
	AvailableRulesFolderPath string
}

func NewRuleService(availableRulesFolderPath string, mongodb *mongo.Database) *RuleService {
	return &RuleService{
		mongodb:                  mongodb,
		AvailableRulesFolderPath: availableRulesFolderPath,
	}
}

func (s *RuleService) ListRules(ctx context.Context, offset int64, limit int64) ([]model.Rule, int64, error) {
	filter := bson.M{"deleted_at": bson.M{"$exists": false}}
	findOptions := options.Find().SetMaxTime(time.Second * 10)

	cursor, err := s.mongodb.Collection(model.RulesCollection.String()).Find(ctx, filter, findOptions)
	if err != nil {
		return []model.Rule{}, 0, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get documents: %w", err))
	}
	defer cursor.Close(ctx)

	rules := make([]model.Rule, 0)
	for cursor.Next(ctx) {
		var rule model.Rule
		err := cursor.Decode(&rule)
		if err != nil {
			return []model.Rule{}, 0, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", err))
		}
		rules = append(rules, rule)
	}
	return rules, int64(len(rules)), nil
}

func (s *RuleService) EnableRule(ctx context.Context, ruleObjectID primitive.ObjectID) (*model.Rule, error) {
	var newRule model.Rule

	err := s.mongodb.Client().UseSession(ctx, func(sessionContext mongo.SessionContext) error {
		var sessionError error
		sessionError = sessionContext.StartTransaction()
		if sessionError != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't start transaction: %w", sessionError))
		}

		sessionCommitter := repository.MongoSessionCommitter(sessionContext, &sessionError)
		defer sessionCommitter()

		var queryRule model.Rule

		filter := bson.M{"_id": ruleObjectID, "deleted_at": bson.M{"$exists": false}}

		oneOptions := options.FindOne().SetMaxTime(time.Second * 10)

		queryResult := s.mongodb.Collection(model.RulesCollection.String()).FindOne(sessionContext, filter, oneOptions)
		if queryResult.Err() != nil {
			sessionError = queryResult.Err()
			if queryResult.Err() == mongo.ErrNoDocuments {
				return NewMongoError(http.StatusNotFound, fmt.Errorf("Document not found: %w", sessionError))
			}
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get document: %w", sessionError))
		}

		sessionError = queryResult.Decode(&queryRule)
		if sessionError != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", sessionError))
		}
		if queryRule.Enabled {
			return NewRuleAlreadyAppliedError(http.StatusBadRequest, fmt.Errorf("%s is already applied", queryRule.Name))
		}

		filter = bson.M{"name_en": queryRule.NameEn}
		var ruleDefinition model.RuleDefinition
		ruleDefinitionResult := s.mongodb.Collection(model.RulesDefinitionsCollection.String()).FindOne(sessionContext, filter, oneOptions)
		if queryResult.Err() != nil {
			sessionError = queryResult.Err()
			return NewRulesError(http.StatusInternalServerError, fmt.Errorf("Error getting rule definition %s from db: %w", queryRule.NameEn, sessionError))
		}
		sessionError = ruleDefinitionResult.Decode(&ruleDefinition)
		if sessionError != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", sessionError))
		}

		newRule.NameEn = ruleDefinition.NameEn
		newRule.CreatedAt = time.Now()
		newRule.NameZh = ruleDefinition.NameZh
		newRule.DescriptionEn = ruleDefinition.DescriptionEn
		newRule.DescriptionZh = ruleDefinition.DescriptionZh
		newRule.Cvss3Score = ruleDefinition.Cvss3Score
		newRule.Enabled = !queryRule.Enabled
		newRule.Cvss3Vector = ruleDefinition.Cvss3Vector
		newRule.Cvss2Score = ruleDefinition.Cvss2Score
		newRule.Cvss2Vector = ruleDefinition.Cvss2Vector
		newRule.ID = primitive.NewObjectIDFromTimestamp(time.Now())
		var insertResult *mongo.InsertOneResult
		insertResult, sessionError = s.mongodb.Collection(model.RulesCollection.String()).InsertOne(sessionContext, newRule)
		if sessionError != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't insert document: %w", sessionError))
		}
		id, ok := insertResult.InsertedID.(primitive.ObjectID)
		if !ok {
			sessionError = fmt.Errorf("Couldn't get document ID")
			return NewMongoError(http.StatusInternalServerError, sessionError)
		}
		newRule.ID = id

		queryRule.DeletedAt = time.Now()
		queryRule.HistoricisedTimestamp = time.Now()
		filter = bson.M{"_id": ruleObjectID}
		update := bson.M{"$set": queryRule}

		_, sessionError = s.mongodb.Collection(model.RulesCollection.String()).UpdateOne(sessionContext, filter, update)
		if sessionError != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't update document: %w", sessionError))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &newRule, nil
}

func (s *RuleService) DisableRule(ctx context.Context, ruleObjectID primitive.ObjectID) (*model.Rule, error) {
	var newRule model.Rule

	err := s.mongodb.Client().UseSession(ctx, func(sessionContext mongo.SessionContext) error {

		var sessionError error
		oneOptions := options.FindOne().SetMaxTime(time.Second * 10)

		sessionError = sessionContext.StartTransaction()
		if sessionError != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't start transaction: %w", sessionError))
		}

		sessionCommitter := repository.MongoSessionCommitter(sessionContext, &sessionError)
		defer sessionCommitter()

		var queryRule model.Rule
		filter := bson.M{"_id": ruleObjectID, "deleted_at": bson.M{"$exists": false}}

		queryResult := s.mongodb.Collection(model.RulesCollection.String()).FindOne(sessionContext, filter, oneOptions)
		if queryResult.Err() != nil {
			sessionError = queryResult.Err()
			if sessionError == mongo.ErrNoDocuments {
				return NewMongoError(http.StatusNotFound, fmt.Errorf("Document not found: %w", sessionError))
			}
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get document: %w", sessionError))
		}

		sessionError = queryResult.Decode(&queryRule)
		if sessionError != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", sessionError))
		}
		if !queryRule.Enabled {
			sessionError = fmt.Errorf("%s is not applied", queryRule.Name)
			return NewRuleNotAppliedError(http.StatusBadRequest, sessionError)
		}

		filter = bson.M{"name_en": queryRule.NameEn}
		var ruleDefinition model.RuleDefinition
		ruleDefinitionResult := s.mongodb.Collection(model.RulesDefinitionsCollection.String()).FindOne(sessionContext, filter)
		if queryResult.Err() != nil {
			sessionError = queryResult.Err()
			return NewRulesError(http.StatusInternalServerError, fmt.Errorf("Error getting rule definitino from db: %w", queryRule.NameEn, sessionError))
		}
		sessionError = ruleDefinitionResult.Decode(&ruleDefinition)
		if sessionError != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", sessionError))
		}

		newRule.NameEn = ruleDefinition.NameEn
		newRule.CreatedAt = time.Now()
		newRule.NameZh = ruleDefinition.NameZh
		newRule.DescriptionEn = ruleDefinition.DescriptionEn
		newRule.DescriptionZh = ruleDefinition.DescriptionZh
		newRule.Cvss3Score = ruleDefinition.Cvss3Score
		newRule.Enabled = !queryRule.Enabled
		newRule.Cvss3Vector = ruleDefinition.Cvss3Vector
		newRule.Cvss2Score = ruleDefinition.Cvss2Score
		newRule.Cvss2Vector = ruleDefinition.Cvss2Vector
		newRule.ID = primitive.NewObjectIDFromTimestamp(time.Now())
		var insertResult *mongo.InsertOneResult
		insertResult, sessionError = s.mongodb.Collection(model.RulesCollection.String()).InsertOne(sessionContext, newRule)
		if sessionError != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't insert document: %w", sessionError))
		}
		id, ok := insertResult.InsertedID.(primitive.ObjectID)
		if !ok {
			sessionError = fmt.Errorf("Couldn't get document ID")
			return NewMongoError(http.StatusInternalServerError, sessionError)
		}
		newRule.ID = id

		queryRule.DeletedAt = time.Now()
		queryRule.HistoricisedTimestamp = time.Now()
		filter = bson.M{"_id": ruleObjectID}
		update := bson.M{"$set": queryRule}

		_, sessionError = s.mongodb.Collection(model.RulesCollection.String()).UpdateOne(sessionContext, filter, update)
		if sessionError != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't update document: %w", sessionError))
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return &newRule, nil
}
