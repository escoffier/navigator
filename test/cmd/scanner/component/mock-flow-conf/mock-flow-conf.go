package mock_flow_conf

import (
	flow_conf "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/flow-conf"
)

var MockFlowConf = []string{"pull-image", "scan-image"}

func init() {
	flow_conf.AddFlowConf("mock-flow", MockFlowConf)
}
