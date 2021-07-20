package main

import (
	"io/ioutil"
	"testing"

	"gopkg.in/yaml.v2"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

func TestParse(t *testing.T)  {
	data, err := ioutil.ReadFile("../../../configs/holmes/rules/holmes_rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var rules []*model.RuleFromYaml
	err = yaml.Unmarshal(data, &rules)
	if err != nil {
		t.Fatal(err)
	}

	var counter int
	for _, rule := range rules {
		if rule.Rule == "" {
			continue
		}
		counter++
		t.Log("check rule", rule.Rule)
		if rule.Suggestion == nil {
			t.Fatal("should have suggestion")
		}

		if kv := rule.Suggestion["zh"]; kv == nil {
			t.Fatal("should have zh suggestion")
		}

		if kv := rule.Suggestion["en"]; kv == nil {
			t.Fatal("should have en suggestion")
		}

		if rule.Suggestion["zh"].Key != "处置建议" || rule.Suggestion["en"].Key != "Suggestions" {
			t.Fatal("unexpected key")
		}

		if (rule.Suggestion["zh"].Value != "删除Pod或者网络隔离Pod，使用免疫防御训练与应用" && rule.Suggestion["zh"].Value != "删除Pod或者网络隔离Pod") ||
			(rule.Suggestion["en"].Value != "Delete the pod or isolate the pod for the network." && rule.Suggestion["en"].Value != "Delete the pod or isolate the pod for the network. Use Immune Defense to train and apply."){
			t.Fatal("unexpected value")
		}
	}

	t.Log("total rules:",counter)
}
