package docker

// RunMongoDB runs a mongodb container in docker
func RunMongoDB() (int, func() error, error) {
	ports, teardown, _, err := RunContainer(
		"docker.io/library/mongo:4.2.0",
		[]string{},
		[]string{},
		"27017/tcp")
	if err != nil {
		return 0, nil, err
	}
	return ports[0], teardown, nil
}
