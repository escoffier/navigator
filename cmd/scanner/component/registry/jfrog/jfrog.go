// Copyright Project Harbor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package jfrog

import (
	"crypto/x509"
	"errors"
	"fmt"

	registry2 "github.com/heroku/docker-registry-client/registry"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

const Version = "jfrog"

// JfrogClient is a JfrogClient to interact with Jfrog
type JfrogClient struct {
	// Client is a Client to access jfrog
	Client *registry2.Registry
	Config registry.RegisterConfig
}

func (c *JfrogClient) GetRegistryConfig() registry.RegisterConfig {
	panic("implement me")
}

func (c *JfrogClient) CheckProject(projectName string) error {
	panic("implement me")
}

func (c *JfrogClient) CreateProject(projectName string, public bool) error {
	panic("implement me")
}

func (c *JfrogClient) GetImage(projectName, fullRepoName, tag string) (*registry.Image, error) {
	panic("implement me")
}

func (c *JfrogClient) DeleteImages(projectName, repoName, digest string) error {
	panic("implement me")
}

func (c *JfrogClient) ListRepos() ([]string, error) {
	// // url := fmt.Sprintf("%s/artifactory/api/repositories", c.Config.URL)
	// url := fmt.Sprintf("%s//artifactory/api/repositories/docker", c.Config.URL)
	// req, err := http.NewRequest("GET", url, nil)
	// if err != nil {
	// 	return nil, fmt.Errorf(fmt.Sprintf("get harbor projects err.%v", err.Error()))
	// }
	// req.SetBasicAuth(c.Config.Username, c.Config.Password)
	// req.Header.Set("Content-Type", "application/json")
	// resp, err := c.Client.Client.Do(req)
	// if err != nil {
	// 	logging.GetLogger().Error().Err(err).Msgf("reqHarbor:%s", err.Error())
	// 	return nil, err
	// }
	// if resp.StatusCode != http.StatusOK && resp.StatusCode >= 500 {
	//
	// 	return nil, fmt.Errorf("status code is %d", resp.StatusCode)
	// }
	// body, err := ioutil.ReadAll(resp.Body)
	// fmt.Println(string(body))
	return nil, nil
}

func (c *JfrogClient) ListImages(extender registry.ImageListExtender) ([]registry.Image, error) {

	images := make([]registry.Image, 0)

	// get all repos
	repos, err := c.ListRepos()
	if err != nil {
		return nil, err
	}
	fmt.Println(repos)

	// for _, repo := range repos {
	// 	tags, err := r.ListRepoTags(repo)
	// 	if err != nil {
	// 		logging.GetLogger().Error().Msgf("get repo %s tags err %v", repo, err)
	// 		continue
	// 	}
	// 	for _, tag := range tags {
	// 		var (
	// 			manifestV2    *schema2.DeserializedManifest
	// 			manifestV2Str []byte
	// 			manifestV1    *schema1.SignedManifest
	// 			manifestV1Str []byte
	// 			configBlob    string
	// 			configDigest  digest.Digest
	// 			imageDigest   string
	// 		)
	// 		manifestV2, err := r.PullImageManifestV2(repo, tag)
	// 		if err == nil {
	// 			// pull config json
	// 			imageDigest, err = ManifestV2Digest(manifestV2)
	// 			if err != nil {
	// 				logging.GetLogger().Error().Msgf("get manifest digest err, repo %s ,digest %s", repo, tag)
	// 				continue
	// 			}
	// 			manifestV2Str, err = manifestV2.MarshalJSON()
	// 			if err != nil {
	// 				logging.GetLogger().Error().Msgf("get manifest string err, repo %s ,digest %s", repo, tag)
	// 				continue
	// 			}
	//
	// 			// pull config json
	// 			configDigest = manifestV2.Config.Digest
	// 			configBlob, err = r.PullConfigBlob(repo, configDigest)
	// 			if err != nil {
	// 				logging.GetLogger().Error().Msgf("get config blob err, repo %s ,digest %s", repo, tag)
	// 				continue
	// 			}
	// 		} else {
	// 			// pull manifest v2 err,try v1
	// 			logging.GetLogger().Info().Msgf("get manifest v2 err %v,try v1, repo %s ,digest %s", err, repo, tag)
	// 			manifestV1, err = r.PullImageManifestV1(repo, tag)
	// 			if err != nil {
	// 				logging.GetLogger().Error().Msgf("get manifest (both v1,v2) err %v, repo %s ,digest %s", err, repo, tag)
	// 				continue
	// 			}
	// 			manifestV1Str, err = manifestV1.MarshalJSON()
	// 			if err != nil {
	// 				logging.GetLogger().Error().Msgf("get manifest v1 str err %v, repo %s ,digest %s", err, repo, tag)
	// 				continue
	// 			}
	//
	// 			// according: github.com/google/go-containerregistry@v0.1.2/pkg/v1/remote/descriptor.go
	// 			// use http-header "Docker-Content-digest" as manifest-v1 image digest
	// 			tmp, err := r.RegistryClient.ManifestDigest(repo, tag)
	// 			if err != nil {
	// 				logging.GetLogger().Error().Msgf("get manifest v1 image list err %v, repo %s ,digest %s", err, repo, tag)
	// 				continue
	// 			}
	// 			imageDigest = tmp.String()
	// 		}
	//
	// 		i := r.MakeImage(repo, tag)
	// 		i.ImageDigest = imageDigest
	// 		i.ManifestV2 = string(manifestV2Str)
	// 		i.ManifestV1 = string(manifestV1Str)
	// 		i.ConfigJson = configBlob
	// 		images = append(images, *i)
	//
	// 		err = extender(r.GetRegistryConfig(), *i)
	// 		if err != nil {
	// 			logging.GetLogger().Error().Msgf("HarborV2 Insert imagelist error %v", err)
	// 			continue
	// 		}
	// 	}
	// }
	return images, nil
}

// OpenRegistry constructs a jfrog JfrogClient
func OpenRegistry(config registry.RegisterConfig) (*JfrogClient, error) {
	var r JfrogClient

	// create client to pull image manifest and config
	r.Config = config
	rc, err := NewRegistryClient(config)
	if err != nil {
		return nil, fmt.Errorf("registryV2:new registry client err:%v", err)
	}
	r.Client = rc

	return &r, nil
}

func NewRegistryClient(config registry.RegisterConfig) (*registry2.Registry, error) {
	hub, err := registry2.New(config.URL, config.Username, config.Password)
	if err != nil && config.SkipTLSVerify {
		// Check for any type of error defined in x509 package.
		_, ok1 := errors.Unwrap(err).(x509.SystemRootsError)
		_, ok2 := errors.Unwrap(err).(x509.CertificateInvalidError)
		_, ok3 := errors.Unwrap(err).(x509.UnknownAuthorityError)
		_, ok4 := errors.Unwrap(err).(x509.HostnameError)
		if ok1 || ok2 || ok3 || ok4 {
			logging.GetLogger().Warn().Msg("Certificate validation failed, but insecure option is on - will retry and skip TLS cert verification")
			hub, err = registry2.NewInsecure(config.URL, config.Username, config.Password)
		}
	}
	if err != nil {
		logging.GetLogger().Err(err).Msg("new registry client failed.")
		return nil, err
	}
	return hub, nil
}
