package main

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

var (
	GlobalDict   = map[string]string{}
	componentMap = map[string]string{
		"ssh":      "SSH",
		"redis":    "Redis",
		"nginx":    "Nginx",
		"postgres": "Postgres",
	}
)

type Control struct {
	Version string  `yaml:"version"`
	ID      int     `yaml:"id"`
	Text    string  `yaml:"text"`
	Groups  []Group `yaml:"groups"`
}

type Group struct {
	ID     int     `yaml:"id"`
	Text   string  `yaml:"text"`
	Checks []Check `yaml:"checks"`
}

type Check struct {
	ID          float64 `yaml:"id"`
	Text        string  `yaml:"text"`
	Audit       string  `yaml:"audit"`
	Tests       Test    `yaml:"tests"`
	Remediation string  `yaml:"remediation"`
	Scored      bool    `yaml:"scored"`
}

type Test struct {
	TestItems []TestItem `yaml:"test_items"`
}

type TestItem struct {
	Flag string `yaml:"flag"`
	Set  bool   `yaml:"set"`
}

func main() {
	components := []string{
		"ssh",
		"redis",
		"nginx",
		"postgres",
	}
	var rules []Rule

	dict := translateFromFile(components)
	GlobalDict = dict

	for _, component := range components {
		// Read the YAML file into a byte slice
		yamlFile, err := ioutil.ReadFile("./cis/" + component + "/definitions.yaml")
		if err != nil {
			log.Fatalf("Failed to read YAML file: %v", err)
		}

		// Unmarshal the YAML into a Control struct
		var control Control
		err = yaml.Unmarshal(yamlFile, &control)
		if err != nil {
			log.Fatalf("Failed to unmarshal YAML: %v", err)
		}

		for _, g := range control.Groups {
			for _, c := range g.Checks {
				rules = append(rules, newRule(c.Text, c.Remediation, component))
				fmt.Println(c.Audit)
			}
		}
	}

	// Marshal to json file
	b, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal: %v", err)
	}
	err = ioutil.WriteFile("rules.json", b, 0644)
	if err != nil {
		log.Fatalf("Failed to write file: %v", err)
	}

}

type KVT struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}

type KVHashT struct {
	En KVT `json:"en"`
	Zh KVT `json:"zh"`
}

type CustomKV struct {
	KVHash KVHashT `json:"KVHash"`
}

type ValueHashTT struct {
	Zh string `json:"zh"`
}

type ValueHashT struct {
	ValueHash ValueHashTT `json:"ValueHash"`
}

type MultiLanguageT struct {
	Category    ValueHashT `json:"category"`
	Description ValueHashT `json:"description"`
	Module      ValueHashT `json:"module"`
}

type Rule struct {
	Version1      string         `json:"Version1"`
	Name          string         `json:"Name"`
	Module        string         `json:"Module"`
	Category      string         `json:"Category"`
	Description   string         `json:"Description"`
	Severity      int            `json:"Severity"`
	CustomKV      []CustomKV     `json:"CustomKV"`
	MultiLanguage MultiLanguageT `json:"MultiLanguage"`
	Status        int            `json:"status"`
}

func newRule(Name, remediation, component string) Rule {
	s := KVHashT{
		En: KVT{
			Key:   "Suggestions",
			Value: remediation,
		},
		Zh: KVT{
			Key:   "处置建议",
			Value: remediation,
		},
	}
	// ruleType := KVHashT{
	// 	En: KVT{
	// 		Key:   "ruleType",
	// 		Value: Name,
	// 	},
	// 	Zh: KVT{
	// 		Key:   "规则类型",
	// 		Value: GlobalDict[Name],
	// 	},
	// }

	highRisk := KVHashT{
		En: KVT{
			Key:   "HighRisk-risk therat",
			Value: "yes",
		},
		Zh: KVT{
			Key:   "是否需要紧急处理",
			Value: "是",
		},
	}
	var customKVs []CustomKV
	customKVs = append(customKVs, CustomKV{KVHash: s},
		CustomKV{KVHash: highRisk})

	mulL := MultiLanguageT{
		Category: ValueHashT{
			ValueHash: ValueHashTT{
				Zh: componentMap[component] + "组件配置检测",
			},
		},
		Description: ValueHashT{
			ValueHash: ValueHashTT{
				Zh: GlobalDict[Name],
			},
		},
		Module: ValueHashT{
			ValueHash: ValueHashTT{
				Zh: "组件安全",
			},
		},
	}

	rule := Rule{
		Version1:      "2",
		Name:          Name,
		Module:        "ContainerSecurity",
		Category:      "CIS/" + componentMap[component],
		Description:   Name,
		Severity:      5,
		CustomKV:      customKVs,
		MultiLanguage: mulL,
		Status:        0,
	}

	return rule
}

type translateWord struct {
	En string `yaml:"en"`
	Zh string `yaml:"zh"`
}

type baiduConfig struct {
	AppID     string `yaml:"app_id"`
	SecretKey string `yaml:"secret_key"`
}

func translateFromFile(components []string) map[string]string {
	var translateWords []translateWord
	//read dict from tmp file
	oldDict, err := ioutil.ReadFile("./dict.yaml")
	if err != nil {
		log.Fatalf("Failed to read YAML file: %v", err)
	}
	err = yaml.Unmarshal(oldDict, &translateWords)
	if err != nil {
		log.Fatalf("Failed to unmarshal YAML: %v", err)
	}
	defer func() {
		//write dict to tmp file
		b, err := yaml.Marshal(translateWords)
		if err != nil {
			log.Fatalf("Failed to marshal: %v", err)
		}
		err = ioutil.WriteFile("./new_dict.yaml", b, 0644)
		if err != nil {
			log.Fatalf("Failed to write file: %v", err)
		}
	}()

	var dict = make(map[string]string)
	for _, word := range translateWords {
		dict[word.En] = word.Zh
	}

	for _, component := range components {
		// Read the YAML file into a byte slice
		yamlFile, err := ioutil.ReadFile("./cis/" + component + "/definitions.yaml")
		if err != nil {
			log.Fatalf("Failed to read YAML file: %v", err)
		}

		// Unmarshal the YAML into a Control struct
		var control Control
		err = yaml.Unmarshal(yamlFile, &control)
		if err != nil {
			log.Fatalf("Failed to unmarshal YAML: %v", err)
		}

		//read baidu config
		bConf, err := ioutil.ReadFile("./baidu.conf")
		if err != nil {
			log.Fatalf("Failed to read YAML file: %v", err)
		}
		var bc baiduConfig
		err = yaml.Unmarshal(bConf, &bc)
		if err != nil {
			log.Fatalf("Failed to unmarshal YAML: %v", err)
		}

		bi := BaiduInfo{AppID: bc.AppID, Salt: Salt(5), SecretKey: bc.SecretKey, From: "en", To: "zh"}

		for _, g := range control.Groups {
			for _, c := range g.Checks {
				if _, ok := dict[c.Text]; !ok {
					bi.Text = c.Text
					t, err := bi.Translate()
					if err != nil {
						log.Fatalf("Failed to translate: %v", err)
						continue
					}
					// log.Println(c.Text, ":", t)
					dict[c.Text] = t
					translateWords = append(translateWords, translateWord{En: c.Text, Zh: t})
					time.Sleep(1 * time.Second)
				}
			}
		}
	}
	return dict
}

//百度翻译开放平台信息
type BaiduInfo struct {
	AppID     string
	Salt      string
	SecretKey string
	From      string
	To        string
	Text      string
}

//返回结果
type TransResult struct {
	From      string    `json:"from"`
	To        string    `json:"to"`
	Result    [1]Result `json:"trans_result"`
	ErrorCode string    `json:"error_code"`
	ErrorMsg  string    `json:"error_msg"`
}
type Result struct {
	Src string `json:"src"`
	Dst string `json:"dst"`
}

//自动生盐
//入口参数为盐的长度
func Salt(l int) string {
	str := "3204958324tekjdafasdlfasldflasdfasfas0q9340218340129sdf"
	bytes := []byte(str)
	result := []byte{}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < l; i++ {
		result = append(result, bytes[r.Intn(len(bytes))])
	}
	return string(result)
}

// 生成32位MD5
func Sign(bi *BaiduInfo) string {
	text := bi.AppID + bi.Text + bi.Salt + bi.SecretKey
	ctx := md5.New()
	ctx.Write([]byte(text))
	return hex.EncodeToString(ctx.Sum(nil))
}

//翻译 传入需要翻译的语句
func (bi *BaiduInfo) Translate() (string, error) {
	url := "https://fanyi-api.baidu.com/api/trans/vip/translate?q=" + bi.Text + "&from=" + bi.From + "&to=" + bi.To + "&appid=" + bi.AppID + "&salt=" + bi.Salt + "&sign=" + Sign(bi)
	url = strings.ReplaceAll(url, " ", "%20")
	resp, err := http.Get(url)
	if err != nil {
		log.Println(err)
		return "", err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println(err)
		return "", err
	}
	var ts TransResult
	err = json.Unmarshal(body, &ts)
	if err != nil {
		log.Println(err)
		return "", err
	}
	if ts.ErrorCode != "" {
		log.Println(ts.ErrorCode, "return")
		return ts.ErrorMsg, nil
	} else {
		return ts.Result[0].Dst, nil
	}
}
