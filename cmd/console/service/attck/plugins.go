package attck

import (
	"context"
	"os"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

const (
	EnvKeyDPTags = "DP_TAGS"
)
type PocSwitchPlugin struct {
	enabledTags map[string]struct{}
}

func newPocSwitchPluginWithGiven(dptags string) PocSwitchPlugin {
	if dptags == "" {
		return PocSwitchPlugin{
			enabledTags: make(map[string]struct{}, 0),
		}
	}
	return PocSwitchPlugin{
		enabledTags: ReadFromConfig(dptags),
	}
}
func NewPocSwitchPlugin() PocSwitchPlugin {
	dptags := os.Getenv(EnvKeyDPTags)
	return newPocSwitchPluginWithGiven(dptags)
}

func (p PocSwitchPlugin) Name() string {
	return "poc_switch"
}
func (p PocSwitchPlugin) GetSession(ctx context.Context, pctx PluginContext) (PluginSession, error) {
	return PocSwitchSession{
		p: p,
	}, nil
}

type PocSwitchSession struct {
	p PocSwitchPlugin
}

func (s PocSwitchSession) Name() string {
	return "poc_switch"
}
func (s PocSwitchSession) ProcessRule(ctx context.Context, r RawRule) (after *RawRule, changed bool, err error) {
	return nil, false, nil
}
func (s PocSwitchSession) TmpProcessRule(ctx context.Context, r model.RuleFromYaml) (after *model.RuleFromYaml, changed bool, err error) {
	isPOC := false
	for _, tag := range r.Tags {
		if tag == "4t" {
			isPOC = true
			break
		}
	}
	if !isPOC {
		return nil, false, nil
	}
	if len(s.p.enabledTags) == 0 {
		return nil, true, nil
	}
	for _, tag := range r.Tags {
		if _, exist := s.p.enabledTags[tag]; exist {
			return nil, false, nil
		}
	}
	return nil, true, nil
}
func (s PocSwitchSession) ProcessMacro(ctx context.Context, m Macro) (after *Macro, changed bool, err error) {
	return nil, false, nil
}
func (s PocSwitchSession) ProcessList(ctx context.Context, l List) (after *List, changed bool, err error) {
	return nil, false, nil
}
func (s PocSwitchSession) NextRule(ctx context.Context) (r *RawRule, more bool) {
	return nil, false
}
func (s PocSwitchSession) NextRuleTmp(ctx context.Context) (r *model.RuleFromYaml, more bool) {
	return nil, false
}
func (s PocSwitchSession) NextMacro(ctx context.Context) (after *Macro, more bool) {
	return nil, false
}
func (s PocSwitchSession) NextList(ctx context.Context) (after *List, more bool) {
	return nil, false
}

type CustomConfigPlugin struct {
	getFunc ConfigsGetFunc
}
type CconfigItem struct {
	RuleKey    string
	CconfigKey string
	Values     []string
}
type ConfigsGetFunc func(ctx context.Context) ([]CconfigItem, error)

func NewCustomConfigPlugin(getFunc ConfigsGetFunc) CustomConfigPlugin {
	return CustomConfigPlugin{getFunc: getFunc}
}

func (p CustomConfigPlugin) Name() string {
	return "custom_configs"
}

type cconfigWithSteps struct {
	cconfig CconfigItem
	steps   []string
}

func (p CustomConfigPlugin) GetSession(ctx context.Context, pctx PluginContext) (PluginSession, error) {
	configs, err := p.getFunc(ctx)
	if err != nil {
		return CustomConfigSession{}, err
	}

	ccs, ok := pctx.GetCustomConfigs(ctx)
	if !ok {

	}
	configs2do := make([]cconfigWithSteps, len(configs))
	for i, c := range configs {
		configs2do[i] = cconfigWithSteps{
			cconfig: c,
		}
		for _, cc := range ccs {
			if c.CconfigKey == cc.Key {
				for _, ccstep := range cc.RulesAppliedSteps {
					if ccstep[0] == c.RuleKey {
						configs2do[i].steps = ccstep
						break
					}
				}
				break
			}
		}

	}
	return CustomConfigSession{
		p:             p,
		pctx:          pctx,
		customConfigs: configs2do,
	}, nil
}

type CustomConfigSession struct {
	p             CustomConfigPlugin
	pctx          PluginContext
	customConfigs []cconfigWithSteps
}

func (s CustomConfigSession) Name() string {
	return s.p.Name()
}
func (s CustomConfigSession) ProcessRule(ctx context.Context, r RawRule) (after *RawRule, changed bool, err error) {
	return nil, false, nil
}
func (s CustomConfigSession) TmpProcessRule(ctx context.Context, r model.RuleFromYaml) (after *model.RuleFromYaml, changed bool, err error) {
	return nil, false, nil
}
func (s CustomConfigSession) ProcessMacro(ctx context.Context, m Macro) (after *Macro, changed bool, err error) {
	return nil, false, nil
}
func (s CustomConfigSession) ProcessList(ctx context.Context, l List) (after *List, changed bool, err error) {
	for _, lconfig := range s.customConfigs {
		if lconfig.cconfig.CconfigKey == l.List {
			for _, item := range lconfig.cconfig.Values {
				found := false
				for _, pv := range l.Items {
					if pv == item {
						found = true
						break
					}
				}
				if !found {
					l.Items = append(l.Items, item)
					changed = true
				}
			}
			if changed {
				return &l, true, nil
			}
		}
	}
	return nil, false, nil
}
func (s CustomConfigSession) NextRule(ctx context.Context) (r *RawRule, more bool) {
	return nil, false
}
func (s CustomConfigSession) NextRuleTmp(ctx context.Context) (r *model.RuleFromYaml, more bool) {
	return nil, false
}
func (s CustomConfigSession) NextMacro(ctx context.Context) (after *Macro, more bool) {
	return nil, false
}
func (s CustomConfigSession) NextList(ctx context.Context) (after *List, more bool) {
	return nil, false
}
