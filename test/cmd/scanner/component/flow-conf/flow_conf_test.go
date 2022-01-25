package flowconf

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	flowConf "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/flow-conf"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

func TestAddFlowConf(t *testing.T) {
	tmpFlow := []string{"mock-pull-image", "mock-scan-image", "mock-score-image"}
	flowConf.AddFlowConf("mock-flow", tmpFlow)
	flowConf.DumpFlowConf()
}

func parseConfigEnv(env []string) []model.EnvKeyValue {
	var res []model.EnvKeyValue
	for _, v := range env {
		index := strings.Index(v, "=")
		if index == -1 {
			continue
		}
		tmpEnv := model.EnvKeyValue{}
		tmpEnv.Key = v[0:index]
		envLen := len(v)
		if index+1 < envLen {
			tmpEnv.Value = v[index+1:]
		}
		res = append(res, tmpEnv)
	}
	return res
}
func TestReadConfig(t *testing.T) {
	configJson1, _ := os.ReadFile("/worker2/tensornavigator/FileServerCache/layerManage/data/sha256:96ed09d2778b7a4e981423df9f2432c9ee5e74465104d6f8c81e64fa8658ed9d/layer.tar")
	configJson2, _ := os.ReadFile("/worker2/tensornavigator/FileServerCache/layerManage/data/sha256:96ed09d2778b7a4e981423df9f2432c9ee5e74465104d6f8c81e64fa8658ed9d/xx.txt")
	t.Log(configJson1)
	t.Log(string(configJson2))
	config := model.ConfigFile{}
	json.Unmarshal(configJson1, &config)
	t.Log(config.Config.Env)
	res := parseConfigEnv(config.Config.Env)
	t.Log(res)
}
