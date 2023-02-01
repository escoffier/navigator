package model

type ConfigMozartStep struct {
	Name   string      `yaml:"name"`
	Params interface{} `yaml:"params"`
}

type ConfigMozartInfoLang struct {
	En string `yaml:"en"`
	Zh string `yaml:"zh"`
}

type ConfigMozartInfo struct {
	Desc       ConfigMozartInfoLang `yaml:"desc"`
	Suggestion ConfigMozartInfoLang `yaml:"suggestion"`
	RuleType   string               `yaml:"rule_type"`
	Priority   string               `yaml:"priority"`
	Urgency    bool                 `yaml:"urgency"`
}

type ConfigMozart struct {
	Name    string             `yaml:"name"`
	Enabled bool               `yaml:"enabled"`
	Trigger string             `yaml:"trigger"`
	Steps   []ConfigMozartStep `yaml:"steps"`
	Info    ConfigMozartInfo   `yaml:"info"`
}

type OriginConfig struct {
	Rule     string         `yaml:"rule"`
	Priority string         `yaml:"priority"`
	Mozart   []ConfigMozart `yaml:"mozart,omitempty"`
	Tags     []string       `yaml:"tags"`
}

type OriginConfigs struct {
	Config []OriginConfig `yaml:"config"`
}
