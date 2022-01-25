package mock_flow_conf

import (
	flowconf "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/flow-conf"
)

var MockFlowConf = []string{"pull-image", "scan-image"}

func init() {
	flowconf.AddFlowConf("mock-flow", MockFlowConf)
}
