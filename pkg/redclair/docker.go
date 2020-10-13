package redclair

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"

	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
)

// Add support for older version of docker

// ManifestJSON ...
type ManifestJSON struct {
	Config string
	Layers []string
}

func createDockerClient() (client.APIClient, error) {
	docker, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return nil, NewDockerError(http.StatusInternalServerError, fmt.Errorf("Failed to create new docker client: %w", err))
	}
	return docker, nil
}

func saveDockerImage(ctx context.Context, imageName string, tmpPath string) (imageID string, layerIds []string, err error) {
	var imageNameStr = strings.Split(imageName, ":")

	log.Info().Str("fs-path", tmpPath).Str("image", imageName).Msgf("Pulling docker image")
	if len(imageNameStr) != 2 {
		err = errors.New("[DOCKER-PULL] image name format error")
		return
	}

	docker, err := createDockerClient()
	if err != nil {
		return "", []string{}, err
	}

	imageReader, err := docker.ImageSave(ctx, []string{imageName})
	// TODO check for image not found error specifically, not just all errors:
	if err != nil {
		log.Info().Err(err).Msg("Error when trying to save image - trying to pull")

		var imagePull io.ReadCloser
		imagePull, err = docker.ImagePull(ctx, imageName, types.ImagePullOptions{})
		if err != nil {
			return "", []string{}, NewDockerError(http.StatusInternalServerError, fmt.Errorf("Error during image pull: %w", err))
		}

		_, err = io.Copy(ioutil.Discard, imagePull)
		// _, err = io.Copy(os.Stdout, imagePull)
		if err != nil {
			return "", []string{}, NewDockerError(http.StatusInternalServerError, fmt.Errorf("Error during reading image pull stdout: %w", err))
		}

		imageReader, err = docker.ImageSave(ctx, []string{imageName})
		if err != nil {
			return "", []string{}, NewDockerError(http.StatusInternalServerError, fmt.Errorf("Error when saving docker image: %w", err))
		}

	}
	defer imageReader.Close()

	if err = untar(imageReader, tmpPath); err != nil {
		return "", []string{}, NewDockerError(http.StatusInternalServerError, fmt.Errorf("Error when untaring docker image: %w", err))
	}

	layerIds, err = getImageLayerIds(tmpPath)
	if err != nil {
		return "", []string{}, NewDockerError(http.StatusInternalServerError, fmt.Errorf("Error when getting image layer ids: %w", err))
	}

	imageID, err = getDockerImageDigest(ctx, docker, imageName)
	if err != nil {
		return "", []string{}, NewDockerError(http.StatusInternalServerError, fmt.Errorf("Error when getting docker image digest: %w", err))
	}

	return
}

func getDockerImageDigest(ctx context.Context, docker client.APIClient, imageName string) (string, error) {
	inspectInfo, _, err := docker.ImageInspectWithRaw(ctx, imageName)
	if err != nil {
		return "", err
	}

	if len(inspectInfo.RepoDigests) > 0 {
		return inspectInfo.RepoDigests[0], nil
	}

	return "", errors.New("empty repo digest array")
}

// getImageLayerIds reads LayerIDs from the manifest.json file
func getImageLayerIds(path string) ([]string, error) {
	manifest, err := readManifestFile(path)
	if err != nil {
		return []string{}, err
	}

	var layers []string
	for _, layer := range manifest[0].Layers {
		layers = append(layers, strings.TrimSuffix(layer, "/layer.tar"))
	}
	return layers, nil
}

// readManifestFile reads the local manifest.json
func readManifestFile(path string) ([]ManifestJSON, error) {
	manifestFile := path + "/manifest.json"
	mf, err := os.Open(manifestFile)
	if err != nil {
		return []ManifestJSON{}, err
	}
	defer mf.Close()

	return parseAndValidateManifestFile(mf)
}

// parseAndValidateManifestFile parses the manifest.json file and validates it
func parseAndValidateManifestFile(manifestFile io.Reader) ([]ManifestJSON, error) {
	var manifest []ManifestJSON
	if err := json.NewDecoder(manifestFile).Decode(&manifest); err != nil {
		return manifest, fmt.Errorf("Could not read Docker image layers: manifest.json is not json: %w", err)
	} else if len(manifest) != 1 {
		return manifest, errors.New("Could not read Docker image layers: manifest.json is not valid")
	} else if len(manifest[0].Layers) == 0 {
		return manifest, errors.New("Could not read Docker image layers: no layers can be found")
	}
	return manifest, nil
}
