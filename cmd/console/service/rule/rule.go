package rule

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gopkg.in/yaml.v2"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type RuleService struct {
	availableRulesFolderPath string
	mongodb                  *mongo.Database
}

func NewRuleService(availableRulesFolderPath string, mongodb *mongo.Database) *RuleService {
	return &RuleService{
		availableRulesFolderPath: availableRulesFolderPath,
		mongodb:                  mongodb,
	}
}

func (s *RuleService) ListRules(ctx context.Context, offset int64, limit int64) ([]model.Rule, int64, error) {
	availableRulesFiles, err := ioutil.ReadDir(s.availableRulesFolderPath)
	if err != nil {
		return []model.Rule{}, 0, NewRulesError(http.StatusInternalServerError, fmt.Errorf("Cannot list rules in dir %s: %w", s.availableRulesFolderPath, err))
	}

	availableRules := make([]model.Rule, 0)

	for _, file := range availableRulesFiles {
		filenameSplit := strings.Split(file.Name(), ".yaml")
		if len(filenameSplit) <= 1 {
			continue
		}
		ruleName := filenameSplit[0]

		var queryRule model.Rule
		filter := bson.M{"name_en": ruleName, "active": true}

		queryResult := s.mongodb.Collection(model.RuleCollection).FindOne(ctx, filter)
		if queryResult.Err() != nil {
			if queryResult.Err() == mongo.ErrNoDocuments {
				var ruleDefinition model.RuleDefinition
				ruleYamlFile, err := ioutil.ReadFile(s.availableRulesFolderPath + "/" + file.Name())
				if err != nil {
					return []model.Rule{}, 0, NewRulesError(http.StatusInternalServerError, fmt.Errorf("Cannot read rule definition %s: %w", s.availableRulesFolderPath+"/"+file.Name(), err))
				}
				err = yaml.Unmarshal(ruleYamlFile, &ruleDefinition)
				if err != nil {
					return []model.Rule{}, 0, NewRulesError(http.StatusInternalServerError, fmt.Errorf("Cannot unmarshal rules definition %s: %w", s.availableRulesFolderPath+"/"+file.Name(), err))
				}
				logging.GetLogger().Info().Str("rule", file.Name()).Msg("Rule successfully parsed")

				queryRule.ID = primitive.NewObjectIDFromTimestamp(time.Now())
				queryRule.Enabled = false
				queryRule.NameEn = ruleDefinition.NameEn
				queryRule.NameZh = ruleDefinition.NameZh
				queryRule.DescriptionEn = ruleDefinition.DescriptionEn
				queryRule.DescriptionZh = ruleDefinition.DescriptionZh
				queryRule.Cvss3Score = ruleDefinition.Cvss3Score
				queryRule.Cvss3Vector = ruleDefinition.Cvss3Vector
				queryRule.Cvss2Score = ruleDefinition.Cvss2Score
				queryRule.Cvss2Vector = ruleDefinition.Cvss2Vector
				insertResult, err := s.mongodb.Collection(model.RuleCollection).InsertOne(ctx, queryRule)
				if err != nil {
					return []model.Rule{}, 0, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't insert document: %w", err))
				}
				id, ok := insertResult.InsertedID.(primitive.ObjectID)
				if !ok {
					return []model.Rule{}, 0, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get document ID: %w", queryResult.Err()))
				}
				queryRule.ID = id
			} else {
				return []model.Rule{}, 0, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get document: %w", queryResult.Err()))
			}
		} else {
			err = queryResult.Decode(&queryRule)
			if err != nil {
				return []model.Rule{}, 0, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", queryResult.Err()))
			}
		}
		availableRules = append(availableRules, queryRule)
	}
	return availableRules, int64(len(availableRules)), nil
}

func (s *RuleService) EnableRule(ctx context.Context, ruleObjectID primitive.ObjectID) (*model.Rule, error) {
	var queryRule model.Rule
	filter := bson.M{"_id": ruleObjectID}

	queryResult := s.mongodb.Collection(model.RuleCollection).FindOne(ctx, filter)
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

	queryRule.Enabled = true
	queryRule.ID = ruleObjectID
	update := bson.M{"$set": queryRule}

	_, err = s.mongodb.Collection(model.RuleCollection).UpdateOne(ctx, filter, update)

	queryResult = s.mongodb.Collection(model.RuleCollection).FindOne(ctx, filter)
	if queryResult.Err() != nil {
		if queryResult.Err() == mongo.ErrNoDocuments {
			return nil, NewMongoError(http.StatusNotFound, fmt.Errorf("Document not found: %w", queryResult.Err()))
		}
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get document: %w", queryResult.Err()))
	}

	err = queryResult.Decode(&queryRule)
	if err != nil {
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", queryResult.Err()))
	}

	return &queryRule, nil
}

func (s *RuleService) DisableRule(ctx context.Context, ruleObjectID primitive.ObjectID) (*model.Rule, error) {
	var queryRule model.Rule
	filter := bson.M{"_id": ruleObjectID}

	queryResult := s.mongodb.Collection(model.RuleCollection).FindOne(ctx, filter)
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

	queryRule.Enabled = false
	queryRule.ID = ruleObjectID
	update := bson.M{"$set": queryRule}

	_, err = s.mongodb.Collection(model.RuleCollection).UpdateOne(ctx, filter, update)

	queryResult = s.mongodb.Collection(model.RuleCollection).FindOne(ctx, filter)
	if queryResult.Err() != nil {
		if queryResult.Err() == mongo.ErrNoDocuments {
			return nil, NewMongoError(http.StatusNotFound, fmt.Errorf("Document not found: %w", queryResult.Err()))
		}
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get document: %w", queryResult.Err()))
	}

	err = queryResult.Decode(&queryRule)
	if err != nil {
		return nil, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", queryResult.Err()))
	}

	return &queryRule, nil
}
