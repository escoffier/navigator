package config

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"regexp"
	"strings"
)

type  RuleFromeYaml struct{
	Rule		string `yaml:"rule"`
	Priority	string `yaml:"priority"`
}

func ParseYamlDiffSet(data []byte, rulesSet map[string]bool)([]string, error) {
	rules := []RuleFromeYaml{}
	err := yaml.Unmarshal(data, &rules)
	if err != nil {
		return nil, err
	}
	var channels []string
	for _, item := range rules {
		if len(item.Rule) == 0 || len(item.Priority) == 0 {
			continue
		}

		reg, _ := regexp.Compile(`\w+`)
		ruleStr := strings.Join(reg.FindAllString(item.Rule, -1), "_")
		channel := fmt.Sprintf("falco.%s.%s", strings.ToLower(item.Priority),
			strings.ToLower(ruleStr))
		channel = strings.ToLower(channel)
		_, ok := rulesSet[channel]
		if ok {
			continue
		}
		channels = append(channels, channel)
	}

	return channels, nil
}

func ParseYamlFromByte(fData []byte) ([]string, error) {
	rules := []RuleFromeYaml{}

	err := yaml.Unmarshal(fData, &rules)

	if err != nil {
		return nil, err
	}

	var channels []string
	for _, item := range rules {
		if len(item.Rule) == 0 || len(item.Priority) == 0 {
			continue
		}
		reg, _ := regexp.Compile(`\w+`)
		ruleStr := strings.Join(reg.FindAllString(item.Rule, -1), "_")
		channel := fmt.Sprintf("falco.%s.%s", strings.ToLower(item.Priority),
			strings.ToLower(ruleStr))
		channels = append(channels, strings.ToLower(channel))
	}

	return channels, nil
}

func ParseYaml(filename *string) ([]string, error) {
	fData, err := ioutil.ReadFile(*filename)
	if err != nil {
		log.Fatalf("Read file %s failed. Error: %s ", *filename, err)
		return nil, err
	}

	return ParseYamlFromByte(fData)
}
