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

func (s *DockerPull) getInspectInfo(ctx context.Context, reg imagesecModel.Registry, im imagesecModel.Image) (*InspectInfo, error) {

	if err := s.login(ctx, reg.Url, reg.Username, reg.PasswordString); err != nil {
		s.Log.Err(err).Msg("scan-image docker pull login")
		return nil, err
	}
	image := im.GetDockerPullImageName()
	if err := s.pullImage(ctx, image); err != nil {
		s.Log.Err(err).Msg("scan-image docker pull pullImage")
		return nil, err
	}

	info, err := s.inspectImage(ctx, image)
	if err != nil {
		s.Log.Err(err).Msg("scan-image docker pull inspectImage")
		return nil, err
	}
	s.Log.Info().
		Int("Layers", len(info.RootFS.Layers)).
		Str("Digest", info.Digest).
		Int("Env", len(info.Config.Env)).
		Int("Entrypoint", len(info.Config.Entrypoint)).
		Str("ImageDigest", image).
		Msg("scan-image docker pull get inspect")

	defer func() { _ = s.rmImage(ctx, image) }()

	return info, nil
}

func (s *DockerPull) pullImage(ctx context.Context, image string) error {

	osCmd := exec.Command("docker", "pull", image)
	err := osCmd.Run()
	if err != nil {
		s.Log.Err(err).Msgf("scan-image docker pull :%s", image)
		return err
	}
	s.Log.Info().Msgf("scan-image docker pull successful :%s", image)
	return nil
}

func (s *DockerPull) inspectImage(ctx context.Context, image string) (*InspectInfo, error) {
	osCmd := exec.Command("docker", "inspect", image)
	stdout, err := osCmd.CombinedOutput()
	if err != nil {
		s.Log.Err(err).Msgf("scan-image docker StdoutPipe:%v ", osCmd.Args)
		return nil, err
	}

	info := make([]InspectInfo, 0)
	if err := json.Unmarshal(stdout, &info); err != nil {
		s.Log.Err(err).Msg("scan-image Unmarshal InspectInfo ")
		return nil, err
	}

	if len(info) == 0 {
		s.Log.Info().Msg("scan-image docker-pull not get manifest")
		return nil, fmt.Errorf("docker-pull not get manifest")
	}

	return &(info[0]), nil
}

type InspectInfo struct {
	Digest string       `json:"Id"`
	RootFS model.RootFS `json:"RootFS"`
	Config model.Config `json:"Config"`
}

func (s *DockerPull) login(ctx context.Context, url, username, password string) error {
	osCmd := exec.Command("docker", "login", "-u", username, "-p", password, getLib(url))
	s.Log.Info().Msgf("scan-image login success %v", osCmd.Args)

	err := osCmd.Run()
	if err != nil {
		s.Log.Err(err).Msgf("scan-image login failed:%v", osCmd.Args)
		return err
	}
	s.Log.Info().Msg("scan-image login successful")
	return nil
}

func (s *DockerPull) rmImage(ctx context.Context, imageName string) error {
	osCmd := exec.Command("docker", "rmi", imageName)

	err := osCmd.Run()
	if err != nil {
		s.Log.Err(err).Msgf("scan-image docker delete image：%s:%v", imageName, osCmd.Args)
		return err
	}
	s.Log.Info().Msgf("scan-image docker delete image：%s", imageName)

	return nil
}

func getLib(url string) string {
	lib := strings.ReplaceAll(url, "http://", "")
	lib = strings.ReplaceAll(lib, "https://", "")

	return lib
}
