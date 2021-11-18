package palace

import (
	"strconv"
	"strings"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type TreeNode struct {
	ClusterKey    string      `json:"clusterKey"`
	Namespace     string      `json:"namespace"`
	PodName       string      `json:"podName"`
	ContainerName string      `json:"containerName"`
	PID           int64       `json:"pid"`
	Pname         string      `json:"pname"`
	Children      []*TreeNode `json:"children"`
}

type SignalElem struct {
	*model.Signal
	Pid      int64             `json:"pid"`
	PName    string            `json:"pname"`
	Rule     *Rule             `json:"rule"`
	CustomKV map[string]string `json:"customKV"`
}

type Rule struct {
	*model.EvtCenterRule
	CustomKV       map[string]string `json:"customKV"`
	DisplayAdapter map[string]string `json:"displayAdapter"`
}

func toApiRule(or *model.EvtCenterRule, language string) *Rule {
	r := new(Rule)
	r.EvtCenterRule = or
	r.CustomKV = make(map[string]string, len(or.CustomKV))
	for _, kv := range or.CustomKV {
		if kval, exist := kv.KVHash[language]; exist {
			if strings.Index(kval.Key, "__internal__") == 0 {
				continue
			}
			r.CustomKV[kval.Key] = kval.Value
		} else if kval, exist := kv.KVHash["en"]; exist {
			if strings.Index(kval.Key, "__internal__") == 0 {
				continue
			}
			r.CustomKV[kval.Key] = kval.Value
		}
	}
	r.DisplayAdapter = make(map[string]string, len(r.MultiLanguage))
	for key, val := range or.MultiLanguage {
		langValue, exist := val.ValueHash[language]
		if exist {
			r.DisplayAdapter[key] = langValue
			switch key {
			case "description":
				r.Description = langValue
			case "category":
				r.Category = langValue
			case "module":
				r.Module = langValue
			}
		}
	}
	r.EvtCenterRule.CustomKV = nil
	r.EvtCenterRule.MultiLanguage = nil
	return r
}

func toApiSignal(s *model.Signal, language string) *SignalElem {
	elem := new(SignalElem)
	elem.Signal = s
	elem.CustomKV = make(map[string]string, len(s.CustomKV))
	for _, kv := range s.CustomKV {
		if kval, exist := kv.KVHash[language]; exist {
			elem.CustomKV[kval.Key] = kval.Value
		} else if kval, exist := kv.KVHash["en"]; exist {
			elem.CustomKV[kval.Key] = kval.Value
		}
		switch kv.KVHash["en"].Key {
		case "pid":
			elem.Pid, _ = strconv.ParseInt(kv.KVHash["en"].Value, 10, 64)
		case "procName":
			elem.PName = kv.KVHash["en"].Value
		}
	}
	elem.Signal.CustomKV = nil

	return elem
}
