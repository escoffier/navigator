package model

const (
	CurrentEngineLargeVersion = 3 // 随holmes版本升级
)

type ConfigMozartStep struct {
	Name     string      `yaml:"name"`
	Params   interface{} `yaml:"params"`
	Optional bool        `yaml:"optional"`
}

type ConfigMozartInfoLang struct {
	Zh string `yaml:"zh"`
	En string `yaml:"en"`
}

type ConfigMozartInfo struct {
	Desc       ConfigMozartInfoLang `yaml:"desc"`
	Suggestion ConfigMozartInfoLang `yaml:"suggestion"`
	RuleType   string               `yaml:"rule_type"`
	Priority   string               `yaml:"priority"`
	Urgency    bool                 `yaml:"urgency"`
}

type ConfigMozartInfoV3 struct {
	Name       ConfigMozartInfoLang `yaml:"name"`
	Desc       ConfigMozartInfoLang `yaml:"desc"`
	Suggestion ConfigMozartInfoLang `yaml:"suggestion"`
	RuleType   string               `yaml:"rule_type"`
	Priority   string               `yaml:"priority"`
	Urgency    bool                 `yaml:"urgency"`
	Tags       []string             `yaml:"tags"`
}

type ConfigMozart struct {
	Name    string             `yaml:"name"`
	Enabled bool               `yaml:"enabled"`
	Trigger string             `yaml:"trigger"`
	Steps   []ConfigMozartStep `yaml:"steps"`
	Info    ConfigMozartInfo   `yaml:"info"`
}

type ConfigMozartMarcoBranches struct {
	Disabled bool               `yaml:"disabled"`
	Steps    []ConfigMozartStep `yaml:"steps"`
	Default  bool               `yaml:"default"`
}

type ConfigMozartMarco struct {
	Key      string                      `yaml:"key"`
	Type     string                      `yaml:"type"`
	Branches []ConfigMozartMarcoBranches `yaml:"branches"`
}

type OriginConfig struct {
	Rule        string              `yaml:"rule"`
	Priority    string              `yaml:"priority"`
	Mozart      []ConfigMozart      `yaml:"mozart,omitempty"`
	MozartMarco []ConfigMozartMarco `yaml:"mozart_marco,omitempty"`
	Tags        []string            `yaml:"tags"`
}

type OriginConfigs struct {
	Config []OriginConfig `yaml:"config"`
}

type MozartYaml struct {
	// rule
	Key       string             `yaml:"key"`
	Disabled  bool               `yaml:"disabled"`
	Hid       string             `yaml:"hid"`
	Condition string             `yaml:"condition"`
	Output    string             `yaml:"output,omitempty"`
	Steps     []ConfigMozartStep `yaml:"steps"`
	Info      ConfigMozartInfoV3 `yaml:"info"`

	// marco+
	Macro string   `yaml:"macro,omitempty"`
	List  string   `yaml:"list,omitempty"`
	Items []string `yaml:"items"`

	// mozart marco+
	Type     string                      `yaml:"type"`
	Branches []ConfigMozartMarcoBranches `yaml:"branches"`
}

type FalcoYaml struct {
	Rule      string   `yaml:"rule,omitempty"`
	Condition string   `yaml:"condition"`
	Desc      string   `yaml:"desc,omitempty"`
	Output    string   `yaml:"output,omitempty"`
	Priority  string   `yaml:"priority,omitempty"`
	Tags      []string `yaml:"tags,omitempty"`

	Macro string `yaml:"macro,omitempty"`

	List  string   `yaml:"list,omitempty"`
	Items []string `yaml:"items"`
}
