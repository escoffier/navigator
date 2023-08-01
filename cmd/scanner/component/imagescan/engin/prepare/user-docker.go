package prepare

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

func getInspectInfo(url, username, password, image string) (*InspectInfo, error) {

	if err := login(url, username, password); err != nil {
		logging.GetLogger().Err(err).Msg("scan-image docker pull login")
		return nil, err
	}

	if err := pullImage(image); err != nil {
		logging.GetLogger().Err(err).Msg("scan-image docker pull pullImage")
		return nil, err
	}

	info, err := inspectImage(image)
	if err != nil {
		logging.GetLogger().Err(err).Msg("scan-image docker pull inspectImage")
		return nil, err
	}
	logging.GetLogger().Info().
		Int("Layers", len(info.RootFS.Layers)).
		Str("Digest", info.Digest).
		Int("Env", len(info.Config.Env)).
		Int("Entrypoint", len(info.Config.Entrypoint)).
		Str("ImageDigest", image).
		Msg("scan-image docker pull get inspect")

	// defer func() { _ = rmImage(image) }()

	return info, nil
}

func pullImage(image string) error {

	osCmd := exec.Command("docker", "pull", image)
	err := osCmd.Run()
	if err != nil {
		logging.GetLogger().Err(err).Msgf("scan-image docker pull :%s", image)
		return err
	}
	logging.GetLogger().Info().Msgf("scan-image docker pull successful :%s", image)
	return nil
}

func inspectImage(image string) (*InspectInfo, error) {
	osCmd := exec.Command("docker", "inspect", image)
	stdout, err := osCmd.CombinedOutput()
	if err != nil {
		logging.GetLogger().Err(err).Msgf("scan-image docker StdoutPipe:%v ", osCmd.Args)
		return nil, err
	}

	info := make([]InspectInfo, 0)
	if err := json.Unmarshal(stdout, &info); err != nil {
		logging.GetLogger().Err(err).Msg("scan-image Unmarshal InspectInfo ")
		return nil, err
	}

	if len(info) == 0 {
		logging.GetLogger().Info().Msg("scan-image docker-pull not get manifest")
		return nil, fmt.Errorf("docker-pull not get manifest")
	}

	return &(info[0]), nil
}

type InspectInfo struct {
	Digest string       `json:"Id"`
	RootFS model.RootFS `json:"RootFS"`
	Config model.Config `json:"Config"`
}

func login(url, username, password string) error {
	osCmd := exec.Command("docker", "login", "-u", username, "-p", password, getLib(url))
	logging.GetLogger().Info().Msgf("scan-image login success %v", osCmd.Args)

	err := osCmd.Run()
	if err != nil {
		logging.GetLogger().Err(err).Msgf("scan-image login failed:%v", osCmd.Args)
		return err
	}
	logging.GetLogger().Info().Msg("scan-image login successful")
	return nil
}

func rmImage(imageName string) error {
	osCmd := exec.Command("docker", "rmi", imageName)

	err := osCmd.Run()
	if err != nil {
		logging.GetLogger().Err(err).Msgf("scan-image docker delete image：%s:%v", imageName, osCmd.Args)
		return err
	}
	logging.GetLogger().Info().Msgf("scan-image docker delete image：%s", imageName)

	return nil
}

func getLib(url string) string {
	lib := strings.ReplaceAll(url, "http://", "")
	lib = strings.ReplaceAll(lib, "https://", "")

	return lib
}
