package daemon

type ProcessData struct {
	HostPid      int    `json:"host_pid"`
	ContainerPid int    `json:"container_pid"`
	Comm         string `json:"comm"`
	UserName     string `json:"user_name"`
	StartTime    string `json:"start_time"`
}

type ListenPort struct {
	Port   int    `json:"port"`
	Proto  string `json:"proto"`
	HostIp string `json:"host_ip"`
}
