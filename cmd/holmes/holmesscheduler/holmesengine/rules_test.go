package holmesengine

import (
	"io"
	"os"
	"testing"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gopkg.in/yaml.v2"
)

func TestRulesMutate(t *testing.T) {
	yamlBytes := []byte(`- rule: The k8s client is executed in a container
- macro: tensorsec_namespace
  condition: k8s.ns.name = tensorsec
- rule: test1
  condition: a = b
`)
	f0 := GetRuleSwitchMutationFunc(map[string]struct{}{"The k8s client is executed in a container": {}}, false)
	f1 := GetTensorsecNamespaceChange("idss")
	f, err := os.Open("../../../../configs/holmes/rules/holmes_rules.yaml")
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	fullBytes, err := io.ReadAll(f)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	toTest := [][]byte{
		yamlBytes, fullBytes,
	}
	for _, ybytes := range toTest {
		var rulesBefore []model.RuleFromYaml
		err = yaml.Unmarshal(ybytes, &rulesBefore)
		if err != nil {
			t.Errorf("%v", err)
			return
		}

		after, err := RulesMutate(ybytes, f0, f1)
		if err != nil {
			t.Errorf("err: %v", err)
		} else {
			var rulesAfter []model.RuleFromYaml
			err = yaml.Unmarshal(after, &rulesAfter)
			if err != nil {
				t.Errorf("yaml unmarhsal err: %v", err)
			} else {
				if len(rulesAfter) != len(rulesBefore) {
					t.Errorf("num is wrong. %+v", rulesAfter)
					return
				}
				for _, rule := range rulesAfter {
					if rule.Rule == "The k8s client is executed in a container" {
						if rule.EnabledPtr == nil || *rule.EnabledPtr == true {
							t.Errorf("mutate error. rule: %v", rule.EnabledPtr)
						}
					} else if rule.Macro == macroNameTensorsecnamespace {
						if rule.Condition != `k8s.ns.name = idss` {
							t.Errorf("mutate error. rule: %v", rule.Condition)
						}
					}
				}
				for _, prule := range rulesBefore {
					found := false
					for _, nrule := range rulesAfter {
						if nrule.Rule == prule.Rule && prule.Rule != "" {
							found = true
							if nrule.Condition != prule.Condition || nrule.HID != prule.HID || nrule.Priority != prule.Priority || nrule.Output != prule.Output {
								t.Errorf("not expecting mutations. newRule: %+v", nrule)
								return
							}
							break
						} else if prule.Macro != "" && prule.Macro == nrule.Macro {
							found = true
							if prule.Condition != nrule.Condition && prule.Macro != macroNameTensorsecnamespace {
								t.Errorf("not expecting mutations. macro: %s newRule: %+v. prevRule: %+v", nrule.Macro, nrule.Condition, prule.Condition)
								return
							}
						} else if prule.List != "" && prule.List == nrule.List {
							found = true
							if len(prule.Items) != len(nrule.Items) {
								t.Errorf("not expecting mutations. list: %s\n newRule: %+v.\n prevRule: %+v.]n afterAll: %s", prule.List, nrule.Items, prule.Items, after)
								return
							}
						} else if prule.RequiredEngineVersion > 0 && prule.RequiredEngineVersion == nrule.RequiredEngineVersion {
							found = true
						}
					}
					if !found {
						t.Errorf("missing rule: %+v", prule)
					}
				}
			}

		}
	}

}
