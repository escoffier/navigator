package microseg

type SingleRule struct {
	PolicyName  string `json:"policy_name"`
	Priority    int    `json:"priority"`
	Direction   string `json:"direction"`
	Action      string `json:"action"`
	Protocol    string `json:"protocol"`
	FromAddress string `json:"from_address"`
	ToAddress   string `json:"to_address"`
}
