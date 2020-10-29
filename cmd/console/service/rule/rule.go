package rule

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"

	"gitlab.com/piccolo_su/vegeta/cmd/console/model/rule"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

const (
	ruleCol = "rule"
)

type RuleService struct {
	availableRulesFolderPath string
	appliedRulesFolderPath   string
	mongodb                  *mongo.Database
}

func NewRuleService(availableRulesFolderPath, appliedRulesFolderPath string, mongodb *mongo.Database) *RuleService {
	return &RuleService{
		availableRulesFolderPath: availableRulesFolderPath,
		appliedRulesFolderPath:   appliedRulesFolderPath,
		mongodb:                  mongodb,
	}
}

func (s *RuleService) ListRules(ctx context.Context, offset int64, limit int64) ([]rule.Rule, int64, error) {
	availableRulesFiles, err := ioutil.ReadDir(s.availableRulesFolderPath)
	if err != nil {
		return []rule.Rule{}, 0, NewRulesError(http.StatusInternalServerError, fmt.Errorf("Cannot list rules in dir %s: %w", s.availableRulesFolderPath, err))
	}

	appliedRulesFiles, err := ioutil.ReadDir(s.appliedRulesFolderPath)
	if err != nil {
		return []rule.Rule{}, 0, NewRulesError(http.StatusInternalServerError, fmt.Errorf("Cannot list rules in dir %s: %w", s.appliedRulesFolderPath, err))
	}

	availableRulesMap := make(map[string]*rule.Rule)
	availableRules := make([]rule.Rule, 0)

	for _, file := range availableRulesFiles {
		filenameSplit := strings.Split(file.Name(), ".yaml")
		if len(filenameSplit) <= 1 {
			continue
		}
		ruleName := filenameSplit[0]
		availableRulesMap[ruleName] = &rule.Rule{
			Name:    ruleName,
			Enabled: false,
		}
	}
	for _, file := range appliedRulesFiles {
		filenameSplit := strings.Split(file.Name(), ".yaml")
		if len(filenameSplit) <= 1 {
			continue
		}
		ruleName := filenameSplit[0]
		if _, ok := availableRulesMap[ruleName]; !ok {
			return []rule.Rule{}, 0, NewRuleDoesntExistError(http.StatusInternalServerError, fmt.Errorf("Applied rule %s does not exist in the set of available rules", ruleName))
		}
		availableRulesMap[ruleName].Enabled = true
	}

	for _, availableRule := range availableRulesMap {
		var queryRule rule.Rule
		filter := bson.M{"name": availableRule.Name}

		queryResult := s.mongodb.Collection(ruleCol).FindOne(ctx, filter)
		if queryResult.Err() != nil {
			if queryResult.Err() == mongo.ErrNoDocuments {
				queryRule.ID = primitive.NewObjectIDFromTimestamp(time.Now())
				queryRule.Enabled = availableRule.Enabled
				queryRule.Name = availableRule.Name
				queryRule.Description = availableRule.Description
				insertResult, err := s.mongodb.Collection(ruleCol).InsertOne(ctx, queryRule)
				if err != nil {
					return []rule.Rule{}, 0, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't insert document: %w", err))
				}
				id, ok := insertResult.InsertedID.(primitive.ObjectID)
				if !ok {
					return []rule.Rule{}, 0, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get document ID: %w", queryResult.Err()))
				}
				queryRule.ID = id
			} else {
				return []rule.Rule{}, 0, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't get document: %w", queryResult.Err()))
			}
		} else {
			err = queryResult.Decode(&queryRule)
			if err != nil {
				return []rule.Rule{}, 0, NewMongoError(http.StatusInternalServerError, fmt.Errorf("Couldn't decode document: %w", queryResult.Err()))
			}
		}
		availableRules = append(availableRules, queryRule)
	}

	return availableRules, int64(len(availableRules)), nil
}

func (s *RuleService) EnableRule(ctx context.Context, ruleObjectID primitive.ObjectID) (*rule.Rule, error) {
	var queryRule rule.Rule
	filter := bson.M{"_id": ruleObjectID}

	queryResult := s.mongodb.Collection(ruleCol).FindOne(ctx, filter)
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

	ruleFilePath := path.Join(s.availableRulesFolderPath, fmt.Sprintf("%s.yaml", queryRule.Name))

	_, err = os.Stat(ruleFilePath)
	if err != nil {
		return nil, NewRulesError(http.StatusInternalServerError, fmt.Errorf("Error while checking rule file existence %s: %w", ruleFilePath, err))
	}

	appliedRuleFilePath := path.Join(s.appliedRulesFolderPath, fmt.Sprintf("%s.yaml", queryRule.Name))

	_, err = os.Stat(appliedRuleFilePath)
	if !os.IsNotExist(err) {
		return nil, NewRuleAlreadyAppliedError(http.StatusBadRequest, fmt.Errorf("%s is already applied", queryRule.Name))
	}

	availableRuleFile, err := os.Open(ruleFilePath)
	if err != nil {
		return nil, NewRulesError(http.StatusInternalServerError, fmt.Errorf("Problem opening rule %s: %w", queryRule.Name, err))
	}
	defer availableRuleFile.Close()

	appliedRuleFile, err := os.Create(appliedRuleFilePath)
	if err != nil {
		return nil, NewRulesError(http.StatusInternalServerError, fmt.Errorf("Problem creating rule file %s: %w", appliedRuleFilePath, err))
	}
	defer appliedRuleFile.Close()

	_, err = io.Copy(appliedRuleFile, availableRuleFile)
	if err != nil {
		removeErr := os.Remove(appliedRuleFilePath)
		if removeErr != nil {
			return nil, NewRulesError(http.StatusInternalServerError, fmt.Errorf("%w error occured. Couldn't remove file %s: %w", err, appliedRuleFilePath, removeErr))
		}
		return nil, NewRulesError(http.StatusInternalServerError, fmt.Errorf("Error while writing applied rule body %s: %w", appliedRuleFilePath, err))
	}

	queryRule.Enabled = true
	queryRule.ID = ruleObjectID
	update := bson.M{"$set": queryRule}

	_, err = s.mongodb.Collection(ruleCol).UpdateOne(ctx, filter, update)

	queryResult = s.mongodb.Collection(ruleCol).FindOne(ctx, filter)
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

func (s *RuleService) DisableRule(ctx context.Context, ruleObjectID primitive.ObjectID) (*rule.Rule, error) {
	var queryRule rule.Rule
	filter := bson.M{"_id": ruleObjectID}

	queryResult := s.mongodb.Collection(ruleCol).FindOne(ctx, filter)
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

	appliedRuleFilePath := path.Join(s.appliedRulesFolderPath, fmt.Sprintf("%s.yaml", queryRule.Name))

	_, err = os.Stat(appliedRuleFilePath)
	if os.IsNotExist(err) {
		return nil, NewRuleNotAppliedError(http.StatusBadRequest, fmt.Errorf("%s is not applied", queryRule.Name))
	}
	if err != nil {
		return nil, NewRulesError(http.StatusInternalServerError, fmt.Errorf("Error while checking rule file existence %s: %w", appliedRuleFilePath, err))
	}

	err = os.Remove(appliedRuleFilePath)
	if err != nil {
		return nil, NewRulesError(http.StatusInternalServerError, fmt.Errorf("Error removing applied rule %s: %w", appliedRuleFilePath, err))
	}

	queryRule.Enabled = false
	queryRule.ID = ruleObjectID
	update := bson.M{"$set": queryRule}

	_, err = s.mongodb.Collection(ruleCol).UpdateOne(ctx, filter, update)

	queryResult = s.mongodb.Collection(ruleCol).FindOne(ctx, filter)
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
