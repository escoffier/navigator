package inject

import (
	"encoding/json"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"io/ioutil"
)

const (
	configFile      = "/etc/webhook/sidecar/proxyconfig.json"
	sidecarTmplFile = "/etc/webhook/sidecar/sidecar-template.yaml"
)

func loadConfig() (*InjectionParameters, error) {

	tmpl, err := ioutil.ReadFile(sidecarTmplFile)
	if err != nil {
		return nil, err
	}

	proxyConfig, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, err
	}

	config := DefaultProxyConfig()
	if err = json.Unmarshal(proxyConfig, config); err != nil {
		logging.GetLogger().Err(err).Msg("parsing proxy config err")
		return nil, err
	}
	logging.GetLogger().Info().Msgf("ProxyConfig: %+v", *config)

	return &InjectionParameters{
		Template:    string(tmpl),
		ProxyConfig: config,
	}, nil
}
