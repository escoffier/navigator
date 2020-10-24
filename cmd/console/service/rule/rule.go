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

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"

	"gitlab.com/piccolo_su/vegeta/cmd/console/model/rule"
)

type RuleService struct {
	AvailableRulesFolderPath string
	AppliedRulesFolderPath   string
}

func NewRuleService(availableRulesFolderPath, appliedRulesFolderPath string) *RuleService {
	return &RuleService{
		AvailableRulesFolderPath: availableRulesFolderPath,
		AppliedRulesFolderPath:   appliedRulesFolderPath,
	}
}

func (s *RuleService) ListRules(ctx context.Context, offset int64, limit int64) ([]rule.Rule, int64, error) {
	availableRulesFiles, err := ioutil.ReadDir(s.AvailableRulesFolderPath)
	if err != nil {
		return []rule.Rule{}, 0, NewRulesError(http.StatusInternalServerError, fmt.Errorf("Cannot list rules in dir %s: %w", s.AvailableRulesFolderPath, err))
	}

	appliedRulesFiles, err := ioutil.ReadDir(s.AppliedRulesFolderPath)
	if err != nil {
		return []rule.Rule{}, 0, NewRulesError(http.StatusInternalServerError, fmt.Errorf("Cannot list rules in dir %s: %w", s.AppliedRulesFolderPath, err))
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
		availableRules = append(availableRules, *availableRule)
	}

	return availableRules, int64(len(availableRules)), nil
}

func (s *RuleService) EnableRule(ctx context.Context, rule string) error {
	ruleFilePath := path.Join(s.AvailableRulesFolderPath, fmt.Sprintf("%s.yaml", rule))

	_, err := os.Stat(ruleFilePath)
	if err != nil {
		return err
	}

	appliedRuleFilePath := path.Join(s.AppliedRulesFolderPath, fmt.Sprintf("%s.yaml", rule))

	_, err = os.Stat(appliedRuleFilePath)
	if !os.IsNotExist(err) {
		return NewRuleAlreadyAppliedError(http.StatusBadRequest, fmt.Errorf("%s is already applied", rule))
	}

	availableRuleFile, err := os.Open(ruleFilePath)
	if err != nil {
		return NewRulesError(http.StatusInternalServerError, fmt.Errorf("Problem opening rule %s: %w", rule, err))
	}
	defer availableRuleFile.Close()

	appliedRuleFile, err := os.Create(appliedRuleFilePath)
	if err != nil {
		return NewRulesError(http.StatusInternalServerError, fmt.Errorf("Problem creating rule file %s: %w", appliedRuleFilePath, err))
	}
	defer appliedRuleFile.Close()

	_, err = io.Copy(appliedRuleFile, availableRuleFile)
	if err != nil {
		removeErr := os.Remove(appliedRuleFilePath)
		if removeErr != nil {
			return NewRulesError(http.StatusInternalServerError, fmt.Errorf("%w error occured. Couldn't remove file %s: %w", err, appliedRuleFilePath, removeErr))
		}
		return NewRulesError(http.StatusInternalServerError, fmt.Errorf("Error while writing applied rule body %s: %w", appliedRuleFilePath, err))
	}
	return nil
}

func (s *RuleService) DisableRule(ctx context.Context, rule string) error {
	appliedRuleFilePath := path.Join(s.AppliedRulesFolderPath, fmt.Sprintf("%s.yaml", rule))

	_, err := os.Stat(appliedRuleFilePath)
	if os.IsNotExist(err) {
		return NewRuleNotAppliedError(http.StatusBadRequest, fmt.Errorf("%s is not applied", rule))
	}
	if err != nil {
		return NewRulesError(http.StatusInternalServerError, fmt.Errorf("Error while checking rule file existence %s: %w", appliedRuleFilePath, err))
	}

	err = os.Remove(appliedRuleFilePath)
	if err != nil {
		return NewRulesError(http.StatusInternalServerError, fmt.Errorf("Error removing applied rule %s: %w", appliedRuleFilePath, err))
	}

	return nil
}
