// Package docker is our docker-related package for testing,
// it uses code from "github.com/docker/docker".
package docker

import (
	"fmt"
	"io"
	"io/ioutil"
	"strconv"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"github.com/facebookarchive/freeport"
	"golang.org/x/net/context"
)

// RunContainer runs a container with an image name, envs and port binding(s)
// if portBinding is in the format of "portproto:hostport", hostport will be used.
// Returns forwarded port(s), container rm callback, and err
func RunContainer(
	imageTag string,
	envs []string,
	command []string,
	portBindings ...string,
) ([]int, func() error, string, error) {
	ctx := context.Background()
	docker, err := client.NewClientWithOpts(client.WithVersion("1.39"))
	if err != nil {
		return nil, nil, "", err
	}

	reader, err := docker.ImagePull(ctx, imageTag, types.ImagePullOptions{})
	if err != nil {
		return nil, nil, "", err
	}
	defer reader.Close()
	_, err = io.Copy(ioutil.Discard, reader)
	if err != nil {
		return nil, nil, "", err
	}

	hostConfig := &container.HostConfig{
		PortBindings: make(nat.PortMap),
	}
	ports := []int{}
	exposed := make(nat.PortSet)
	if len(portBindings) > 0 {
		for _, pb := range portBindings {
			var port int
			if strings.Contains(pb, ":") {
				tokens := strings.Split(pb, ":")
				pb = tokens[0]

				port, err = strconv.Atoi(tokens[1])
				if err != nil {
					return nil, nil, "", err
				}
			} else {
				port, err = freeport.Get()
				if err != nil {
					return nil, nil, "", err
				}
			}

			ports = append(ports, port)

			portproto := nat.Port(pb)
			hostConfig.PortBindings[portproto] = []nat.PortBinding{
				{
					HostIP:   "0.0.0.0",
					HostPort: fmt.Sprintf("%d", port),
				},
			}

			exposed[portproto] = struct{}{}
		}
	}

	resp, err := docker.ContainerCreate(ctx, &container.Config{
		Image:        imageTag,
		Env:          envs,
		ExposedPorts: exposed,
		Cmd:          command,
	}, hostConfig, nil, "")
	if err != nil {
		return nil, nil, "", err
	}

	remove := func() error {
		return docker.ContainerRemove(ctx, resp.ID, types.ContainerRemoveOptions{
			RemoveVolumes: true,
			Force:         true,
		})
	}
	return ports, remove, resp.ID[:10],
		docker.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{})
}
