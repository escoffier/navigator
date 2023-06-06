package holmes

import (
	"bytes"
	"encoding/binary"
	"strings"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/cryption"
	"gitlab.com/security-rd/go-pkg/logging"
	gmodel "gitlab.com/security-rd/go-pkg/model"
	"gopkg.in/yaml.v2"
)

const (
	headerKeyCconfigInit = "custom_config_inits"
)

func ToThrBytes(ruleBytes []byte, versionNum [2]uint16) ([]byte, error) {
	data, md5, blockNum := cryption.EncryptionRules(ruleBytes)
	header := &cryption.FileHeader{BlockNum: blockNum, Version: versionNum}
	header.Init(md5)

	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, header)
	if err != nil {
		return nil, err
	}

	thrBytes := make([]byte, 0, buf.Len()+len(data))
	thrBytes = append(thrBytes, buf.Bytes()...)
	thrBytes = append(thrBytes, data...)
	return thrBytes, nil
}

type CconfigInitConfig struct {
	Key               string         `yaml:"key"`
	Name              model.HolaJSON `yaml:"name"`
	Effect            model.HolaJSON `yaml:"effect"`
	Prompt            model.HolaJSON `yaml:"prompt"`
	Type              string         `yaml:"type"`
	RulesAppliedSteps [][]string     `yaml:"rulesAppliedSteps"`
}

type Macro struct {
	Macro     string `yaml:"macro"`
	Condition string `yaml:"condition"`
}
type List struct {
	List  string   `yaml:"list"`
	Items []string `yaml:"items"`
}

type ItemsParsed struct {
	CustomConfigInits []*CconfigInitConfig
	Macros            []*Macro
	Lists             []*List
	Rules             []*gmodel.UserRuleYaml
}

func ParseHolmesFile(raw []byte) (ItemsParsed, error) {
	str := string(raw)
	mark := "##" + headerKeyCconfigInit
	endMark := mark + " END"
	pos := strings.Index(str, mark)
	endPos := strings.Index(str, endMark)
	otherStr := str
	result := ItemsParsed{}
	configsStr := ""
	if pos >= 0 && endPos >= 0 {
		otherStr = str[0:pos] + str[endPos+len(endMark):]
		configsStr = str[pos:endPos]
	}
	if len(configsStr) > 0 {
		configs := make([]*CconfigInitConfig, 0, 10)
		err := yaml.Unmarshal([]byte(configsStr), &configs)
		if err != nil {
			logging.Get().Err(err).Str("str", configsStr).Msg("parse init configs error")
			return result, err
		}
		result.CustomConfigInits = configs
	}

	items := make([]*gmodel.UserRuleYaml, 0, 150)
	err := yaml.Unmarshal([]byte(otherStr), &items)
	if err != nil {
		logging.Get().Err(err).Str("str", otherStr).Msg("parse other str error")
		return result, err
	}
	for _, item := range items {
		if item.List != "" {
			result.Lists = append(result.Lists, &List{
				List:  item.List,
				Items: item.Items,
			})
		} else if item.Macro != "" {
			result.Macros = append(result.Macros, &Macro{
				Macro:     item.Macro,
				Condition: item.Condition,
			})
		} else {
			result.Rules = append(result.Rules, item)
		}
	}
	return result, nil
}
