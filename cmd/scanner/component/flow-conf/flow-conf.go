// Package flowconf define all image scan action
package flowconf

import (
	"errors"
	"fmt"
)

type FlowConf []string

var defaultImageScanFlow = []string{"pull-image", "scan-image", "save-result"}
var nilFlow = []string{""}
var onlyPull = []string{"pull-image"}

const (
	DefaultImageScanFlowName = "defaultImageScanFlow"
)

var flowConfs = map[string][]string{
	"defaultImageScanFlow": defaultImageScanFlow,
	"nilFlow":              nilFlow,
	"onlyPullFlow":         onlyPull,
}

func GetFlowConf(name string) ([]string, error) {
	v, ok := flowConfs[name]
	if !ok {
		return nil, fmt.Errorf("not find: %s 's flow conf", name)
	}
	return v, nil
}

func AddFlowConf(name string, flow []string) error {
	_, ok := flowConfs[name]
	if ok {
		return errors.New("flow already exist")
	}
	flowConfs[name] = flow
	return nil
}

func DumpFlowConf() {
	for k, v := range flowConfs {
		fmt.Printf("flow name:%s\n", k)
		for _, h := range v {
			fmt.Printf("%s ", h)
		}
		fmt.Print("\n")
	}
}
