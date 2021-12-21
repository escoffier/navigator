package docker

import (
	"context"
	"net"
	"time"

	"github.com/docker/docker/client"
	json "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/pkg/daemon"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"k8s.io/client-go/kubernetes"
)

const unixSockFile = "/tmp/setns.sock"

type NsenterData struct {
	sockClient *net.UnixConn
	dockerCli  *client.Client
	k8sClient  *kubernetes.Clientset
}

func DockerNewClient(k8sClient *kubernetes.Clientset) (*NsenterData, error) {
	dockerCli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return nil, errors.Errorf("docker new client failed, %v", err)
	}
	//create unix socket
	addr, err := net.ResolveUnixAddr("unix", unixSockFile)
	if err != nil {
		return nil, errors.Errorf("create unix socket client failed, %v", err)
	}
	//unix socket dial
	sockClient, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		return nil, errors.Errorf("unix socket client dial failed, %v", err)
	}
	//print log
	logging.GetLogger().Info().Msgf("docker new client success!")
	return &NsenterData{sockClient: sockClient, dockerCli: dockerCli, k8sClient: k8sClient}, nil
}

func (nse NsenterData) Close() {
	if nse.dockerCli != nil {
		nse.dockerCli.Close()
	}

	if nse.sockClient != nil {
		nse.sockClient.Close()
	}
}

func (nse NsenterData) GetContainerPid(containerId string) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	container, err := nse.dockerCli.ContainerInspect(ctx, containerId)
	if err != nil {
		return 0, errors.Errorf("container inspace failed, %v", err)
	}

	if container.State.Pid <= 0 {
		return 0, errors.Errorf("get container's pid failed, pid : %v", container.State.Pid)
	}

	return container.State.Pid, nil
}

func (nse NsenterData) GetProcessName(netinfo *daemon.PidAssociateMnt) (string, error) {
	if nse.sockClient == nil {
		return "", errors.Errorf("udp client is nil")
	}

	data, err := json.Marshal(netinfo)
	if err != nil {
		return "", errors.Errorf("json marshal failed, %v", err)
	}

	_, err = nse.sockClient.Write(data)
	if err != nil {
		return "", errors.Errorf("send net info to setns process failed, %v", err)
	}

	var length int
	rcvBuf := make([]byte, 128)
	timeout := make(chan struct{})
	go func() {
		length, err = nse.sockClient.Read(rcvBuf)
		if err != nil {
			logging.GetLogger().Error().Msgf("read unix socket response data failed, %v", err)
			return
		}
		timeout <- struct{}{}
	}()

	select {
	case <-time.After(time.Second * 2):
		length = 0
	case <-timeout:
		var proc daemon.ProcessInfo
		err = json.Unmarshal(rcvBuf[:length], &proc)
		if err != nil {
			return "", errors.Errorf("json unmarshal with setns process response data failed, %v", err)
		}
		//
		if netinfo.Pid != proc.Pid {
			return "", errors.Errorf("process id is error, local pid : %v, response pid : %v", netinfo.Pid, proc.Pid)
		}
		return proc.ProcName, nil
	}

	return "", errors.Errorf("read udp response timeout")
}
