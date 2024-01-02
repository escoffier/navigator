package prepare

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type DockerPull struct {
	Log *scannerUtils.LogEvent
}

func NewDockerPull() *DockerPull {
	s := &DockerPull{
		Log: scannerUtils.NewLogEvent(
			scannerUtils.WithModule(consts.ModuleImageScan),
			scannerUtils.WithSubModule("DockerPull"),
		)}
	return s
}

func (s *DockerPull) PullImage(ctx context.Context, image string) error {

	osCmd := exec.Command("docker", "pull", image)
	err := osCmd.Run()
	if err != nil {
		s.Log.Err(err).Msgf("docker pull :%s", image)
		return err
	}
	s.Log.Info().Str("image", image).Msg("docker pull successful")
	return nil
}

func (s *DockerPull) InspectImage(ctx context.Context, reg imagesecModel.Registry, im imagesecModel.Image) (*InspectInfo, error) {
	if err := s.Login(ctx, reg.Url, reg.Username, reg.PasswordString); err != nil {
		s.Log.Err(err).Msg("docker login")
		return nil, err
	}
	image := im.GetDockerPullImageName()
	if err := s.PullImage(ctx, image); err != nil {
		s.Log.Err(err).Msg("docker pull pullImage")
		return nil, err
	}
	osCmd := exec.Command("docker", "inspect", image)
	stdout, err := osCmd.CombinedOutput()
	if err != nil {
		s.Log.Err(err).Msgf("docker StdoutPipe:%v ", osCmd.Args)
		return nil, err
	}

	infos := make([]InspectInfo, 0)
	if err := json.Unmarshal(stdout, &infos); err != nil {
		s.Log.Err(err).Msg("Unmarshal InspectInfo ")
		return nil, err
	}

	if len(infos) == 0 {
		s.Log.Info().Msg("docker-pull not get manifest")
		return nil, fmt.Errorf("docker-pull not get manifest")
	}
	info := infos[0]

	s.Log.Info().
		Int("Layers", len(info.RootFS.Layers)).
		Str("Digest", info.Digest).
		Int("Env", len(info.Config.Env)).
		Int("Entrypoint", len(info.Config.Entrypoint)).
		Str("ImageDigest", image).
		Msg("docker pull get inspect")

	defer func() { _ = s.RmImage(ctx, image) }()

	return &info, nil
}

type InspectInfo struct {
	Digest string       `json:"Id"`
	RootFS model.RootFS `json:"RootFS"`
	Config model.Config `json:"Config"`
}

func (s *DockerPull) Login(ctx context.Context, url, username, password string) error {
	osCmd := exec.Command("docker", "login", "-u", username, "-p", password, getLib(url))
	s.Log.Info().Msgf("login success %v", osCmd.Args)

	err := osCmd.Run()
	if err != nil {
		s.Log.Err(err).Msgf("login failed:%v", osCmd.Args)
		return err
	}
	s.Log.Info().Msg("login successful")
	return nil
}

func (s *DockerPull) RmImage(ctx context.Context, imageName string) error {
	osCmd := exec.Command("docker", "rmi", imageName)

	err := osCmd.Run()
	if err != nil {
		s.Log.Err(err).Msgf("docker delete image：%s:%v", imageName, osCmd.Args)
		return err
	}
	s.Log.Info().Msgf("docker delete image：%s", imageName)

	return nil
}

func getLib(url string) string {
	lib := strings.ReplaceAll(url, "http://", "")
	lib = strings.ReplaceAll(lib, "https://", "")

	return lib
}
