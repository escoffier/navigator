package attck

import (
	"io/ioutil"
	"log"
	"os"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"
	"gitlab.com/piccolo_su/vegeta/pkg/cryption"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestParseItems(t *testing.T) {
	data, err := ioutil.ReadFile("encrypt_rule.data")
	if err != nil {
		t.Fatal(err)
	}

	copyData := make([]byte, len(data))
	copy(copyData, data)

	header, rulesContext, _, err := cryption.ReadRulesData(data)
	if err != nil {
		t.Fatal(err)
	}
	version, rules, err := parseItems(header, rulesContext)
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
