package config

import (
	"io/ioutil"
	"testing"
)

func TestParseItems(t *testing.T) {
	data, err := ioutil.ReadFile("encrypt_rule.data")
	if err != nil {
		t.Fatal(err)
	}

	copyData := make([]byte, len(data))
	copy(copyData, data)

	version, rules, err := parseItems(data)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(version)
	for _, rule := range rules {
		t.Log("name:", rule.name, "description:", rule.description,
			"ruleType:", rule.ruleType, "adapter:", rule.adapter,
			"severity:", rule.severity, "hthreats:", rule.hthreats)
	}

	for i := 0; i < len(data); i++ {
		if data[i] != copyData[i] {
			t.Fatal("data changed")
		}
	}
}
