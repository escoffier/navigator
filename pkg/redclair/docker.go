package redclair

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
)

// Add support for older version of docker

// ManifestJSON ...
type ManifestJSON struct {
	Config string
	Layers []string
}

func createDockerClient() client.APIClient {
	docker, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		log.Fatal().Msgf("Could not create a Docker client: %v", err)
	}
	return docker
}

// SaveDockerImage ...
func SaveDockerImage(
	imageName string,
	tmpPath string,
) (imageID string, layerIds []string, err error) {
	var imageNameStr = strings.Split(imageName, ":")

	log.Info().Str("fs-path", tmpPath).Str("image", imageName).Msgf("Pulling docker image")
	if len(imageNameStr) != 2 {
		err = errors.New("[DOCKER-PULL] image name format error")
		return
	}

	docker := createDockerClient()
	imageReader, err := docker.ImageSave(context.Background(), []string{imageName})
	if err != nil {
		var imagePull io.ReadCloser
		imagePull, err = docker.ImagePull(context.Background(), imageName, types.ImagePullOptions{})
		if err != nil {
			log.Error().Msgf("%v", err)
		} else {
			_, err = io.Copy(ioutil.Discard, imagePull)
			// _, err = io.Copy(os.Stdout, imagePull)
			if err != nil {
				log.Fatal().Msgf("%v", err)
				return
			}

			imageReader, err = docker.ImageSave(context.Background(), []string{imageName})
			if err != nil {
				log.Fatal().Msgf("%v", err)
				return
			}
		}
	}

	defer imageReader.Close()

	log.Info().Msgf("Untaring file in %s, %v", tmpPath, imageReader)
	if err = untar(imageReader, tmpPath); err != nil {
		log.Fatal().Msgf("Could not save Docker image: could not untar [%s]: %v", imageName, err)
		return
	}

	layerIds = getImageLayerIds(tmpPath)
	imageID, err = GetDockerImageDigest(imageName)
	if err != nil {
		return
	}

	return
}

//GetDockerImageDigest get digest for the image given its name and tag
func GetDockerImageDigest(imageName string) (string, error) {
	docker := createDockerClient()

	inspectInfo, _, err := docker.ImageInspectWithRaw(context.Background(), imageName)
	if err != nil {
		log.Fatal().Msgf("Cannot inspect image %s, %v", imageName, err)
		return "", err
	}

	if len(inspectInfo.RepoDigests) > 0 {
		return inspectInfo.RepoDigests[0], nil
	}

	return "", errors.New("empty repo digest array")
}

// getImageLayerIds reads LayerIDs from the manifest.json file
func getImageLayerIds(path string) []string {
	manifest := readManifestFile(path)

	var layers []string
	for _, layer := range manifest[0].Layers {
		layers = append(layers, strings.TrimSuffix(layer, "/layer.tar"))
	}
	return layers
}

// readManifestFile reads the local manifest.json
func readManifestFile(path string) []ManifestJSON {
	manifestFile := path + "/manifest.json"
	mf, err := os.Open(manifestFile)
	if err != nil {
		log.Fatal().Msgf("Could not read Docker image layers: could not open [%s]: %v", manifestFile, err)
	}
	defer mf.Close()

	return parseAndValidateManifestFile(mf)
}

// parseAndValidateManifestFile parses the manifest.json file and validates it
func parseAndValidateManifestFile(manifestFile io.Reader) []ManifestJSON {
	var manifest []ManifestJSON
	if err := json.NewDecoder(manifestFile).Decode(&manifest); err != nil {
		log.Fatal().Msgf("Could not read Docker image layers: manifest.json is not json: %v", err)
	} else if len(manifest) != 1 {
		log.Fatal().Msgf("Could not read Docker image layers: manifest.json is not valid")
	} else if len(manifest[0].Layers) == 0 {
		log.Fatal().Msgf("Could not read Docker image layers: no layers can be found")
	}
	return manifest
}
