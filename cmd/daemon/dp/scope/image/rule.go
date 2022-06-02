package image

import (
	"encoding/json"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/dp/scope"
	"gitlab.com/security-rd/go-pkg/logging"
	"regexp"
)

const (
	version = "scope-image"
)

type ScopeImageConfig struct {
	RegexImageName string `json:"regex-image-name"`
}

type ScopeImage struct {
	config *ScopeImageConfig
	regExp *regexp.Regexp
}

func (s *ScopeImage) Match(param scope.RuleParam) (bool, error) {
	p, ok := param["scopeImage"]
	if !ok {
		return false, fmt.Errorf("not find image name in param")
	}
	var imageName string
	switch p.(type) {
	case string:
		imageName = p.(string)
	default:
		return false, fmt.Errorf("param: imageName not string")
	}

	if s.regExp != nil {
		return s.regExp.MatchString(imageName), nil
	}

	// if not set regexp,return not match
	return false, nil
}

func init() {
	err := scope.Register(version, NewScopeImage)
	if err != nil {
		logging.Get().Err(err).Msg("register scope image driver failed")
		return
	}
	logging.Get().Info().Msg("register scope image driver ok")
}

func NewScopeImage(config scope.RuleConfig) (scope.Rule, error) {
	byt, err := json.Marshal(config.Options)
	if err != nil {
		logging.Get().
			Err(err).
			Interface("options", config.Options).
			Msg("scope image marshal config failed")
		return nil, err
	}

	conf := new(ScopeImageConfig)
	if err := json.Unmarshal(byt, conf); err != nil {
		logging.Get().
			Err(err).
			Bytes("config", byt).
			Msg("scope image Unmarshal config failed")
		return nil, err
	}
	s := &ScopeImage{
		config: conf,
	}

	r, err := regexp.Compile(conf.RegexImageName)
	if err != nil {
		logging.Get().Err(err).Str("rule", conf.RegexImageName).Msg("scope image make regexp failed")
		s.regExp = nil
	} else {
		s.regExp = r
	}

	return s, nil
}
