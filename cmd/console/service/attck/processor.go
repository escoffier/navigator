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

type mlTmp struct {
	Macro     string `yaml:"macro"`
	Condition string `yaml:"condition"`
	List      string `yaml:"list"`
	Items     []any  `yaml:"items"`
}
type ProcessPlugin interface {
	Name() string
	GetSession(ctx context.Context, pctx PluginContext) (PluginSession, error)
}
type PluginSession interface {
	Name() string
	ProcessRule(ctx context.Context, r RawRule) (after *RawRule, changed bool, err error)                          // There could be changes on the rules format. We don't use yaml to parse.
	TmpProcessRule(ctx context.Context, r model.RuleFromYaml) (after *model.RuleFromYaml, changed bool, err error) // tmp for simplicity
	ProcessMacro(ctx context.Context, m Macro) (after *Macro, changed bool, err error)
	ProcessList(ctx context.Context, l List) (after *List, changed bool, err error)
	NextRule(ctx context.Context) (r *RawRule, more bool)
	NextRuleTmp(ctx context.Context) (r *model.RuleFromYaml, more bool)
	NextMacro(ctx context.Context) (after *Macro, more bool)
	NextList(ctx context.Context) (after *List, more bool)
}

type PluginContext struct {
	rules    []*RawRule
	macros   []*Macro
	lists    []*List
	rulesTmp []model.RuleFromYaml

	configs []*CconfigInitConfig
}

func (c *PluginContext) GetRule(ctx context.Context, ruleKey string) (*HolmesRule, bool) {
	// TODO not used now
	return nil, false
}
func (c *PluginContext) GetRuleTmp(ctx context.Context, ruleKey string) (model.RuleFromYaml, bool) {
	// TMP
	for _, r := range c.rulesTmp {
		if r.Rule == ruleKey {
			return r, true
		}
	}
	return model.RuleFromYaml{}, false
}
func (c *PluginContext) GetMacro(ctx context.Context, macro string) (*Macro, bool) {
	for _, m := range c.macros {
		if m.Macro == macro {
			return m, true
		}
	}
	return nil, false
}
func (c *PluginContext) GetList(ctx context.Context, list string) (*List, bool) {
	for _, l := range c.lists {
		if l.List == list {
			return l, true
		}
	}
	return nil, false
}
func (c *PluginContext) GetCustomConfigs(ctx context.Context) ([]*CconfigInitConfig, bool) {
	return c.configs, true
}

type RawRule struct {
	key   string
	lines []string
}
type Processor struct {
	plugins []ProcessPlugin

	// original
	rulesFile      string
	rulesTmp       []model.RuleFromYaml
	macroListsFile string
	mozartFile     []byte
	configs        []*CconfigInitConfig
}

func (p *Processor) AddPlugin(pp ProcessPlugin) error {
	p.plugins = append(p.plugins, pp)
	return nil
}

func macroListParse(macroListsFile string) ([]*Macro, []*List, error) {
	mlTmp := make([]mlTmp, 0, 50)
	err := yaml.Unmarshal([]byte(macroListsFile), &mlTmp)
	if err != nil {
		return nil, nil, err
	}
	macros := make([]*Macro, 0, len(mlTmp)*2/3)
	lists := make([]*List, 0, len(mlTmp)*2/3)
	for _, item := range mlTmp {
		if len(item.Macro) > 0 {
			macros = append(macros, &Macro{
				Macro:     item.Macro,
				Condition: item.Condition,
			})
		} else if len(item.List) > 0 {
			lists = append(lists, &List{
				List:  item.List,
				Items: item.Items,
			})
		}
	}
	return macros, lists, nil
}

func rulesParse(rulesFile string) ([]RawRule, error) {
	// TODO no need to implement, wait @liuwenyuan to merge Mozart
	return nil, nil
}

func (p *Processor) Process(ctx context.Context) ([]byte, PluginContext, error) {
	macros, lists, err := macroListParse(p.macroListsFile)
	if err != nil {
		return nil, PluginContext{}, err
	}
	pctx := PluginContext{
		macros:   macros,
		lists:    lists,
		configs:  p.configs,
		rulesTmp: p.rulesTmp,
	}

	psessions := make([]PluginSession, 0, len(p.plugins))
	for _, p := range p.plugins {
		ps, err := p.GetSession(ctx, pctx)
		if err != nil {
			logging.Get().Err(err).Msg("get session of plugin error")
			continue
		}
		psessions = append(psessions, ps)
	}

	newLists := make([]*List, 0, len(pctx.lists))
	for _, list := range pctx.lists {
		for _, ps := range psessions {
			newList, changed, pperr := ps.ProcessList(ctx, *list)
			if pperr != nil {
				logging.Get().Err(pperr).Str("plugin", ps.Name()).Interface("list", *list).Msg("plugin process list error")
				continue
			} else if changed {

				if newList != nil {
					list = newList
					sb := strings.Builder{}
					for _, item := range newList.Items {
						sb.WriteString(item.(string))
						sb.WriteByte(',')
					}
					logging.Get().Info().Str("plugin", ps.Name()).Str("items", sb.String()).Msg("plugin process list done")
				} else {
					list = nil
					logging.Get().Info().Str("plugin", ps.Name()).Msg("plugin process list remove done")
					break
				}
			}
		}
		if list != nil {
			newLists = append(newLists, list)
		}
	}
	pctx.lists = newLists

	newMacros := make([]*Macro, 0, len(pctx.macros))
	for _, macro := range pctx.macros {
		for _, ps := range psessions {
			newMacro, changed, pperr := ps.ProcessMacro(ctx, *macro)
			if pperr != nil {
				logging.Get().Err(pperr).Str("plugin", ps.Name()).Interface("macro", *macro).Msg("plugin process macro error")
				continue
			} else if changed {
				logging.Get().Info().Str("plugin", ps.Name()).Msg("plugin process macro done")
				if newMacro != nil {
					macro = newMacro
				} else {
					macro = nil
					break
				}
			}
		}
		if macro != nil {
			newMacros = append(newMacros, macro)
		}
	}
	pctx.macros = newMacros

	newRules := make([]model.RuleFromYaml, 0, len(pctx.rulesTmp))
	for i, _ := range pctx.rulesTmp {
		for _, ps := range psessions {
			newRule, changed, pperr := ps.TmpProcessRule(ctx, p.rulesTmp[i])
			if pperr != nil {
				logging.Get().Err(pperr).Str("plugin", ps.Name()).Str("rule", p.rulesTmp[i].Rule).Msg("plugin process rule error")
				continue
			} else if changed {
				logging.Get().Info().Str("plugin", ps.Name()).Str("rkey", p.rulesTmp[i].Rule).Msg("plugin process rule done")
				if newRule != nil {
					p.rulesTmp[i] = *newRule
				} else {
					p.rulesTmp[i] = model.RuleFromYaml{}
					break
				}
			}
		}
		if pctx.rulesTmp[i].Rule != "" {
			newRules = append(newRules, pctx.rulesTmp[i])
		}
	}
	pctx.rulesTmp = newRules

	for _, ps := range psessions {
		for i := 0; i < 1000; i++ {
			nextList, more := ps.NextList(ctx)
			if nextList != nil {
				pctx.lists = append(pctx.lists, nextList)
			}
			if !more {
				break
			}
		}
		for i := 0; i < 1000; i++ {
			nextMacro, more := ps.NextMacro(ctx)
			if nextMacro != nil {
				pctx.macros = append(pctx.macros, nextMacro)
			}
			if !more {
				break
			}
		}

		for i := 0; i < 1000; i++ {
			nextRule, more := ps.NextRuleTmp(ctx)
			if nextRule != nil {
				pctx.rulesTmp = append(pctx.rulesTmp, *nextRule)
			}
			if !more {
				break
			}
		}
	}

	outputBui := bytes.Buffer{}
	rbytes, err := yaml.Marshal(pctx.rulesTmp)
	if err != nil {
		return nil, pctx, err
	}
	outputBui.Write(rbytes)

	mbytes, err := yaml.Marshal(pctx.macros)
	if err != nil {
		return nil, pctx, err
	}
	outputBui.Write(mbytes)

	lbytes, err := yaml.Marshal(pctx.lists)
	if err != nil {
		return nil, pctx, err
	}
	outputBui.Write(lbytes)

	outputBui.WriteByte('\n')
	outputBui.Write(p.mozartFile)

	outputBytes := outputBui.Bytes()

	return outputBytes, pctx, nil
}

func ProcessorBuilder(ctx context.Context, decodedRaw []byte) (*Processor, *RulesStore, error) {
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
	proc := &Processor{
		plugins:        make([]ProcessPlugin, 0, 5),
		rulesFile:      rulesFile.String(),
		rulesTmp:       rulesRaw,
		macroListsFile: macroListsFile.String(),
		mozartFile:     []byte(mozartsFile.String()),
		configs:        initConfigs,
	}
	return proc, store, nil
}
