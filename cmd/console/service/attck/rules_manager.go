package attck

import (
	"bytes"
	"context"
	"strings"

	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rtdetect"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
	"gopkg.in/yaml.v2"
)

const (
	headerKeyCconfigInit = "custom_config_inits"
	headerKeyAttck       = "attck_rule_type="
	headerKeyMacroList   = "macros_lists"
	headerKeyMozart      = "mozart"
)

type HolmesRule struct {
	Key         string
	Name        model.HolaJSON
	Description model.HolaJSON
	Category    model.HolaJSON
	Severity    uint8
	Hthreats    uint8
	Disabled    bool
	Tags        []string

	rawLines   []string
	isInternal bool
}

type RulesStore struct {
	rules       []*HolmesRule
	rmap        map[string]*HolmesRule
	configsInit []*CconfigInitConfig
}

func (s *RulesStore) GetCconfigInitConfigs() []*CconfigInitConfig {
	return s.configsInit
}
func (s *RulesStore) ISearch(ctx context.Context, kw string) ([]*HolmesRule, error) {
	candidates := make([]*HolmesRule, 0, 3)
	for _, r := range s.rules {
		if r.isInternal {
			continue
		}
		for lang, target := range r.Name {
			if lang == "en" {
				if strings.Contains(strings.ToLower(target), strings.ToLower(kw)) {
					candidates = append(candidates, r)
					break
				}
			} else if strings.Contains(target, kw) {
				candidates = append(candidates, r)
				break
			}
		}
	}
	return candidates, nil
}

func (s *RulesStore) GetRule(ctx context.Context, ruleKey string) (*HolmesRule, bool) {
	r, exist := s.rmap[ruleKey]
	return r, exist
}

func (s *RulesStore) addRule(r *HolmesRule) {
	s.rules = append(s.rules, r)
	s.rmap[r.Key] = r
}
func (s *RulesStore) setCconfigInit(init []*CconfigInitConfig) {
	s.configsInit = init
}

func newStore() *RulesStore {
	return &RulesStore{
		rules: make([]*HolmesRule, 0, 110),
		rmap:  make(map[string]*HolmesRule, 110),
	}
}

type CconfigInitConfig struct {
	Key               string         `yaml:"key"`
	Name              model.HolaJSON `yaml:"name"`
	Effect            model.HolaJSON `yaml:"effect"`
	Type              string         `yaml:"type"`
	RulesAppliedSteps [][]string     `yaml:"rulesAppliedSteps"`
}

type Macro struct {
	Macro     string `yaml:"macro"`
	Condition string `yaml:"condition"`
}
type List struct {
	List  string `yaml:"list"`
	Items []any  `yaml:"items"`
}

type ProcessPlugin interface {
	ProcessRule(ctx context.Context, lines []string, pctx PluginContext) (after []string, changed bool, err error) // There could be changes on the rules format. We don't use yaml to parse.
	ProcessMacro(ctx context.Context, m Macro, pctx PluginContext) (after *Macro, changed bool, err error)
	ProcessList(ctx context.Context, l List, pctx PluginContext) (after *List, changed bool, err error)
	NextRule(ctx context.Context, pctx PluginContext) (after []string, changed bool, err error)
	NextMacro(ctx context.Context, pctx PluginContext) (after *Macro, changed bool, err error)
	NextList(ctx context.Context, pctx PluginContext) (after *List, changed bool, err error)
}

type PluginContext struct {
}

func (c PluginContext) GetRule(ctx context.Context, ruleKey string) (*HolmesRule, bool) {
	return nil, false
}
func (c PluginContext) GetMacro(ctx context.Context, macro string) (*Macro, bool) {
	return nil, false
}
func (c PluginContext) GetList(ctx context.Context, list string) (*Macro, bool) {
	return nil, false
}

type RulesProcessor struct {
}

func ProcessorBuilder(ctx context.Context, decodedRaw []byte) (*RulesProcessor, *RulesStore, error) {
	decoded := string(decodedRaw)

	seperatedFiles := strings.Split(decoded, "##")

	rulesFile := new(bytes.Buffer)
	macroListsFile := new(strings.Builder)
	mozartsFile := new(strings.Builder)
	cconfigInitsFile := new(bytes.Buffer)

	for _, filestr := range seperatedFiles {
		if strings.Index(filestr, headerKeyAttck) == 0 {
			brPos := strings.IndexRune(filestr, '\n')
			if brPos > 0 {
				filestr = filestr[brPos:]
			}
			rulesFile.WriteString(filestr)
		} else if strings.Index(filestr, headerKeyMacroList) == 0 {
			brPos := strings.IndexRune(filestr, '\n')
			if brPos > 0 {
				filestr = filestr[brPos:]
			}
			macroListsFile.WriteString(filestr)
		} else if strings.Index(filestr, headerKeyCconfigInit) == 0 {
			brPos := strings.IndexRune(filestr, '\n')
			if brPos > 0 {
				filestr = filestr[brPos:]
			}
			cconfigInitsFile.WriteString(filestr)
		} else if strings.Index(filestr, headerKeyMozart) == 0 {
			brPos := strings.IndexRune(filestr, '\n')
			if brPos > 0 {
				filestr = filestr[brPos:]
			}
			mozartsFile.WriteString(filestr)
		}
	}

	store := newStore()
	initConfigs := make([]*CconfigInitConfig, 0, 10)
	err := yaml.Unmarshal(cconfigInitsFile.Bytes(), &initConfigs)
	if err != nil {
		logging.Get().Err(err).Str("raw", cconfigInitsFile.String()).Msg("unmarshal init configs error")
		return nil, nil, err
	}
	store.setCconfigInit(initConfigs)

	rulesRaw := make([]model.RuleFromYaml, 0, 120)
	err = yaml.Unmarshal(rulesFile.Bytes(), &rulesRaw)
	if err != nil {
		logging.Get().Err(err).Msg("unmarshal rules error")
		return nil, nil, err
	}
	for _, r := range rulesRaw {
		_, ritem, pferr := parseFalcoRule(r)
		if pferr != nil {
			logging.Get().Err(pferr).Interface("rule", r).Msg("parse falco rule error")
			continue
		}
		if ritem.name == "" {
			continue
		}
		// 只是关联规则，不应展示，，是内部规则
		isInternal := false
		if !util.ContainsString(r.Tags, "triggered") && util.ContainsString(r.Tags, "related") {
			isInternal = true
		}
		// 触发规则严重级别较低，不应展示，是内部规则
		if util.ContainsString(r.Tags, "triggered") && !rtdetect.ComparePriority(r.Priority, "ERROR") {
			isInternal = true
		}
		store.addRule(&HolmesRule{
			Key: ritem.name,
			Name: model.HolaJSON{
				string(lang.LanguageZH): ritem.adapter[string(lang.LanguageZH)][descriptionKey],
				string(lang.LanguageEN): ritem.name,
			},
			Description: model.HolaJSON{
				string(lang.LanguageZH): ritem.adapter[string(lang.LanguageZH)][descriptionKey],
				string(lang.LanguageEN): ritem.adapter[string(lang.LanguageEN)][descriptionKey],
			},
			Category: model.HolaJSON{
				string(lang.LanguageZH): ritem.adapter[string(lang.LanguageZH)][typeKey],
				string(lang.LanguageEN): ritem.adapter[string(lang.LanguageEN)][typeKey],
			},
			Severity:   ritem.severity,
			Hthreats:   ritem.hthreats,
			Tags:       r.Tags,
			isInternal: isInternal,
		})
	}
	// TODO processor
	return nil, store, nil
}
