package rule

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/go-redis/redis/v8"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	rcache "gitlab.com/piccolo_su/vegeta/pkg/cache"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/mongotools"
	"gitlab.com/piccolo_su/vegeta/pkg/repository"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type RuleService struct {
	mongodb                  *mongotools.DatabaseWrapper
	AvailableRulesFolderPath string
	rulesCache               *rcache.RulesCache
}

func NewRuleService(ctx context.Context, availableRulesFolderPath string, mongodb *mongotools.DatabaseWrapper, redisClient *redis.Client) *RuleService {
	return &RuleService{
		mongodb:                  mongodb,
		AvailableRulesFolderPath: availableRulesFolderPath,
		rulesCache:               rcache.NewRulesCache(ctx, mongodb, redisClient),
	}
}

func (s *RuleService) ListRules(ctx context.Context, offset int64, limit int64) ([]model.Rule, int64, error) {
	rulesIds, docNum, err := s.rulesCache.GetItems(ctx, offset, limit)
	if err != nil {
		return nil, 0, NewRedisCacheError(http.StatusInternalServerError, fmt.Errorf("Failed to get results from cache: %w", err))
	}

	items := make([]model.Rule, len(rulesIds))

	ids := make([]primitive.ObjectID, len(rulesIds))
	for i := range rulesIds {
		ids[i] = rulesIds[i].ID
	}

	filter := bson.D{{"_id", bson.D{{"$in", ids}}}}
	opts := options.Find()
	opts.SetMaxTime(time.Second * 10)
	opts.SetSort(bson.D{{"created_at", util.SortOrderToInt("desc")}})

	coll := s.mongodb.Get().Collection(model.RulesCollection.String())
	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*10)
	defer mongoCtxCancel()

	cur, err := coll.Find(mongoCtx, filter, opts)
	if err != nil {
		return nil, 0, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Could not find documents: %w", err))
	}
	defer cur.Close(mongoCtx)
	var ruleNo int = 0
	for cur.Next(mongoCtx) {
		var rule model.Rule
		err := cur.Decode(&rule)
		if err != nil {
			return nil, 0, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", err))
		}

		items[ruleNo] = rule
		ruleNo++
	}
	err = cur.Err()
	if err != nil {
		return nil, 0, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Mongo cursor error: %w", err))
	}

	return items, docNum, nil
}

func (s *RuleService) EnableRule(ctx context.Context, ruleObjectID primitive.ObjectID) (*model.Rule, error) {
	var newRule model.Rule

	err := s.mongodb.Get().Client().UseSession(ctx, func(sessionContext mongo.SessionContext) error {
		sessionError := sessionContext.StartTransaction()
		if sessionError != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't start transaction: %w", sessionError))
		}

		defer repository.MongoSessionCommitter(sessionContext, &sessionError)()

		var queryRule model.Rule

		filter := bson.M{"_id": ruleObjectID, "deleted_at": bson.M{"$exists": false}}

		oneOptions := options.FindOne().SetMaxTime(time.Second * 10)

		queryResult := s.mongodb.Get().Collection(model.RulesCollection.String()).FindOne(sessionContext, filter, oneOptions)
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
		ruleDefinitionResult := s.mongodb.Get().Collection(model.RulesDefinitionsCollection.String()).FindOne(sessionContext, filter, oneOptions)
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
		insertResult, sessionError = s.mongodb.Get().Collection(model.RulesCollection.String()).InsertOne(sessionContext, newRule)
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

		_, sessionError = s.mongodb.Get().Collection(model.RulesCollection.String()).UpdateOne(sessionContext, filter, update)
		if sessionError != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't update document: %w", sessionError))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	err = s.rulesCache.RefreshCache()
	if err != nil {
		return nil, NewAnError(
			http.StatusInternalServerError, fmt.Errorf("Couldn't refresh cache: %w", err))
	}

	return &newRule, nil
}

func (s *RuleService) DisableRule(ctx context.Context, ruleObjectID primitive.ObjectID) (*model.Rule, error) {
	var newRule model.Rule

	err := s.mongodb.Get().Client().UseSession(ctx, func(sessionContext mongo.SessionContext) error {
		sessionError := sessionContext.StartTransaction()
		if sessionError != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't start transaction: %w", sessionError))
		}

		defer repository.MongoSessionCommitter(sessionContext, &sessionError)()

		oneOptions := options.FindOne().SetMaxTime(time.Second * 10)

		var queryRule model.Rule
		filter := bson.M{"_id": ruleObjectID, "deleted_at": bson.M{"$exists": false}}

		queryResult := s.mongodb.Get().Collection(model.RulesCollection.String()).FindOne(sessionContext, filter, oneOptions)
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
		ruleDefinitionResult := s.mongodb.Get().Collection(model.RulesDefinitionsCollection.String()).FindOne(sessionContext, filter)
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
		insertResult, sessionError = s.mongodb.Get().Collection(model.RulesCollection.String()).InsertOne(sessionContext, newRule)
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

		_, sessionError = s.mongodb.Get().Collection(model.RulesCollection.String()).UpdateOne(sessionContext, filter, update)
		if sessionError != nil {
			return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't update document: %w", sessionError))
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	err = s.rulesCache.RefreshCache()
	if err != nil {
		return nil, NewAnError(
			http.StatusInternalServerError, fmt.Errorf("Couldn't refresh cache: %w", err))
	}

	return &newRule, nil
}
