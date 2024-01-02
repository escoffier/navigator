package consts

const (
	ImageTarTimeoutENV              = "IMG_TAR_TIMEOUT_ENV"
	ContainerdRuntime               = "containerd"
	CrioRuntime                     = "crio"
	DockerRuntime                   = "docker"
	DockerRequestTimeout            = 3
	ContainerdRequestTimeout        = 30
	ENVDockerSocketAddr             = "DOCKER_SOCKET_ADDR"
	ENVContainerdSocketAddr         = "CONTAINERD_SOCKET_ADDR"
	EnvCRIOSocketAddr               = "CRIO_SOCKET_ADDR"
	DefaultDockerSocket      string = "unix:///var/run/docker.sock"
	DefaultCRIOSocket        string = "unix:///var/run/crio/crio.sock"
	DefaultContainerdSocket  string = "unix:///var/run/containerd/containerd.sock"
	DockerDefaultNamespace          = "default"
)
