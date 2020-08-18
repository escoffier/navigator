package docker

// RunEtcd runs an etcd container in docker
func RunEtcd() (int, func() error, error) {
	ports, teardown, _, err := RunContainer(
		"quay.io/coreos/etcd:v3.4.0",
		[]string{},
		[]string{
			"/usr/local/bin/etcd",
			"--data-dir=/etcd-data",
			"--name=default",
			"--advertise-client-urls=http://0.0.0.0:2379",
			"--listen-client-urls=http://0.0.0.0:2379",
		},
		"2379/tcp")
	if err != nil {
		return 0, nil, err
	}
	return ports[0], teardown, nil
}
