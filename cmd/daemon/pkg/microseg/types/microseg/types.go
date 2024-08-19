package microseg

type ConfigDumpReq struct {
	UUID        string `json:"uuid"`
	MessageType int    `json:"msg_type"`
}

type SingleRule struct {
	PolicyName  string `json:"policy_name"`
	Priority    int    `json:"priority"`
	Direction   string `json:"direction"`
	Action      string `json:"action"`
	Protocol    string `json:"protocol"`
	FromAddress string `json:"from_address"`
	ToAddress   string `json:"to_address"`
}

type RespBody struct {
	InboundRules  []SingleRule `json:"inbound_rules"`
	OutboundRules []SingleRule `json:"outbound_rules"`
}
type ConfigDumpResp struct {
	MessageType int      `json:"msg_type"`
	UUID        string   `json:"uuid"`
	Status      int      `json:"status"`
	Body        RespBody `json:"body"`
}
