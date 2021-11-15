package hunter

import (
	"encoding/json"
	"os"
	"testing"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type category struct {
	En       string               `json:"en"`
	Zh       string               `json:"zh"`
	Children map[string]*category `json:"children,omitempty"`
}

func TestLoadConf(t *testing.T) {
	confPath := "../../../../configs/kube-scanner/translate.json"
	var conf model.KubeHunterTranslateConf
	jsonBytes, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}

	err = json.Unmarshal(jsonBytes, &conf)
	if err != nil {
		t.Fatal(err)
	}

	var hash = make(map[string]*category)
	for key, vulnerability := range conf.Vulnerabilities {
		enItem, ok := vulnerability["en"]
		if !ok {
			t.Fatal("no en item", key)
		}
		zhItem, ok := vulnerability["zh"]
		if !ok {
			t.Fatal("no zh item", key)
		}

		if _, ok := hash[enItem.Category]; !ok {
			hash[enItem.Category] = &category{
				En: enItem.Category,
				Zh: zhItem.Category,
			}
		}

		c := hash[enItem.Category]
		if len(c.Children) == 0 {
			c.Children = make(map[string]*category)
		}

		c.Children[enItem.SubCategory] = &category{En: enItem.SubCategory, Zh: zhItem.SubCategory}
	}

	var categoryList = make([]*category, 0, len(hash))
	for _, v := range hash {
		categoryList = append(categoryList, v)
	}

	categoryInfo, err := json.MarshalIndent(categoryList, "", "	")
	if err != nil {
		t.Fatal(err)
	}

	t.Log(string(categoryInfo))
}
