package rule

import (
	"context"
	"fmt"
	"net/http"
	"time"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
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
<<<<<<< HEAD
	filter := bson.M{"active": true}

	findOptions := options.Find().SetMaxTime(time.Second * 10)
=======
	filter := bson.M{"deleted_at": bson.M{"$exists": false}}
	findOptions := options.Find()
>>>>>>> master

	cursor, err := s.mongodb.Collection(model.RuleCollection).Find(ctx, filter, findOptions)
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
	var queryRule model.Rule
	filter := bson.M{"_id": ruleObjectID, "deleted_at": bson.M{"$exists": false}}

	oneOptions := options.FindOne().SetMaxTime(time.Second * 10)

	queryResult := s.mongodb.Collection(model.RuleCollection).FindOne(ctx, filter, oneOptions)
	if queryResult.Err() != nil {
		if queryResult.Err() == mongo.ErrNoDocuments {
			return nil, NewMongoError(http.StatusNotFound, fmt.Errorf("Document not found: %w", queryResult.Err()))
		}
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get document: %w", queryResult.Err()))
	}

	err := queryResult.Decode(&queryRule)
	if err != nil {
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", queryResult.Err()))
	}
	if queryRule.Enabled {
		return nil, NewRuleAlreadyAppliedError(http.StatusBadRequest, fmt.Errorf("%s is already applied", queryRule.Name))
	}

	filter = bson.M{"name_en": queryRule.NameEn}
	var ruleDefinition model.RuleDefinition
	ruleDefinitionResult := s.mongodb.Collection(model.RuleDefinitionCollection).FindOne(ctx, filter, oneOptions)
	if queryResult.Err() != nil {
		return nil, NewRulesError(http.StatusInternalServerError, fmt.Errorf("Error getting rule definitino from db: %w", queryRule.NameEn, err))
	}
	err = ruleDefinitionResult.Decode(&ruleDefinition)
	if err != nil {
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", queryResult.Err()))
	}

	var newRule model.Rule

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
	insertResult, err := s.mongodb.Collection(model.RuleCollection).InsertOne(ctx, newRule)
	if err != nil {
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't insert document: %w", err))
	}
	id, ok := insertResult.InsertedID.(primitive.ObjectID)
	if !ok {
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get document ID: %w", queryResult.Err()))
	}
	newRule.ID = id

	queryRule.DeletedAt = time.Now()
	queryRule.HistoricisedTimestamp = time.Now()
	filter = bson.M{"_id": ruleObjectID}
	update := bson.M{"$set": queryRule}
	_, err = s.mongodb.Collection(model.RuleCollection).UpdateOne(ctx, filter, update)
	if err != nil {
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't update document: %w", err))
	}

	return &newRule, nil
}

func (s *RuleService) DisableRule(ctx context.Context, ruleObjectID primitive.ObjectID) (*model.Rule, error) {
	var queryRule model.Rule
	filter := bson.M{"_id": ruleObjectID, "deleted_at": bson.M{"$exists": false}}

	oneOptions := options.FindOne().SetMaxTime(time.Second * 10)

	queryResult := s.mongodb.Collection(model.RuleCollection).FindOne(ctx, filter, oneOptions)
	if queryResult.Err() != nil {
		if queryResult.Err() == mongo.ErrNoDocuments {
			return nil, NewMongoError(http.StatusNotFound, fmt.Errorf("Document not found: %w", queryResult.Err()))
		}
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get document: %w", queryResult.Err()))
	}

	err := queryResult.Decode(&queryRule)
	if err != nil {
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", queryResult.Err()))
	}
	if !queryRule.Enabled {
		return nil, NewRuleNotAppliedError(http.StatusBadRequest, fmt.Errorf("%s is not applied", queryRule.Name))
	}

	filter = bson.M{"name_en": queryRule.NameEn}
	var ruleDefinition model.RuleDefinition
	ruleDefinitionResult := s.mongodb.Collection(model.RuleDefinitionCollection).FindOne(ctx, filter, oneOptions)
	if queryResult.Err() != nil {
		return nil, NewRulesError(http.StatusInternalServerError, fmt.Errorf("Error getting rule definitino from db: %w", queryRule.NameEn, err))
	}
	err = ruleDefinitionResult.Decode(&ruleDefinition)
	if err != nil {
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", queryResult.Err()))
	}

	var newRule model.Rule

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
	insertResult, err := s.mongodb.Collection(model.RuleCollection).InsertOne(ctx, newRule)
	if err != nil {
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't insert document: %w", err))
	}
	id, ok := insertResult.InsertedID.(primitive.ObjectID)
	if !ok {
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get document ID: %w", queryResult.Err()))
	}
	newRule.ID = id

	queryRule.DeletedAt = time.Now()
	queryRule.HistoricisedTimestamp = time.Now()
	filter = bson.M{"_id": ruleObjectID}
	update := bson.M{"$set": queryRule}

	_, err = s.mongodb.Collection(model.RuleCollection).UpdateOne(ctx, filter, update)
	if err != nil {
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't update document: %w", err))
	}

	return &newRule, nil
}
