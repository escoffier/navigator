package rule

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path"
	"strings"

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
		log.Fatal(err)
	}

	appliedRulesFiles, err := ioutil.ReadDir(s.AppliedRulesFolderPath)
	if err != nil {
		log.Fatal(err)
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
			return []rule.Rule{}, 0, fmt.Errorf("Applied rule %s does not exist in the set of available rules", ruleName)
		}
		availableRulesMap[ruleName].Enabled = true
	}

	for _, availableRule := range availableRulesMap {
		availableRules = append(availableRules, *availableRule)
	}

	return availableRules, 0, nil
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
		return fmt.Errorf("%s is already applied", rule)
	}

	availableRuleFile, err := os.Open(ruleFilePath)
	if err != nil {
		return err
	}
	defer availableRuleFile.Close()

	appliedRuleFile, err := os.Create(appliedRuleFilePath)
	if err != nil {
		return err
	}
	defer appliedRuleFile.Close()

	_, err = io.Copy(appliedRuleFile, availableRuleFile)
	if err != nil {
		removeErr := os.Remove(appliedRuleFilePath)
		if removeErr != nil {
			return fmt.Errorf("%s error occured. Couldn't remove file: %s", err, removeErr)
		}
		return err
	}
	return nil
}

func (s *RuleService) DisableRule(ctx context.Context, rule string) error {
	appliedRuleFilePath := path.Join(s.AppliedRulesFolderPath, fmt.Sprintf("%s.yaml", rule))

	_, err := os.Stat(appliedRuleFilePath)
	if os.IsNotExist(err) {
		return fmt.Errorf("%s is not applied", rule)
	}
	if err != nil {
		return err
	}

	err = os.Remove(appliedRuleFilePath)
	if err != nil {
		return err
	}

	return nil
}
