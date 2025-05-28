package scannerUtils

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/docker/distribution/manifest/schema2"
	registry2 "github.com/heroku/docker-registry-client/registry"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
)

type Hash struct {
	// Algorithm holds the algorithm used to compute the hash.
	Algorithm string

	// Hex holds the hex portion of the content hash.
	Hex string
}

func (h Hash) String() string {
	return fmt.Sprintf("%s:%s", h.Algorithm, h.Hex)
}

func pullImageManifest(cli *registry2.Registry, repo, digest string, mediaType string) (*schema2.Manifest, []byte, error) {
	// 使用自定义的 Accept 头来支持 v2 manifest
	url := Url(cli, "/v2/%s/manifests/%s", repo, digest)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, nil, err
	}

	// 添加多种媒体类型支持
	req.Header.Add("Accept", mediaType)

	// 使用 RegistryClient 的 Client 发送请求
	// 注意：RegistryClient 已经处理了认证，所以这里不需要手动添加
	resp, err := cli.Client.Do(req)
	if err != nil {
		logging.Get().Err(err).Msg("pull image manifest")
		return nil, nil, err
	}
	defer util.CloseBodyWithLog(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logging.Get().Err(err).Msg("pull image can not read body")
		return nil, nil, err
	}

	manifest := &schema2.Manifest{}
	if err := json.Unmarshal(body, manifest); err != nil {
		logging.Get().Info().Str("mediaType", mediaType).Str("body", string(body)).
			Str("repo", repo).Str("digest", digest).Msg("PullImageManifest get body")
		logging.Get().Err(err).Msg("pull image can not unmarshall")
		return nil, nil, err
	}

	return manifest, body, nil
}

// DeserializedManifest 自定义的反序列化 Manifest 结构体，绕过 MediaType 检查
type DeserializedManifest struct {
	schema2.Manifest
	// canonical is the canonical byte representation of the Manifest.
	canonical []byte
}

func (m *DeserializedManifest) MarshalJSON() ([]byte, error) {
	if len(m.canonical) > 0 {
		return m.canonical, nil
	}
	return json.Marshal(m.Manifest)
}

// UnmarshalJSON 自定义反序列化方法，绕过 MediaType 检查
func (m *DeserializedManifest) UnmarshalJSON(b []byte) error {
	m.canonical = make([]byte, len(b))
	copy(m.canonical, b)

	// 直接反序列化到 Manifest 结构体，不进行 MediaType 检查
	return json.Unmarshal(b, &m.Manifest)
}

func PullImageManifestV2(cli *registry2.Registry, repo, digest string) (*DeserializedManifest, error) {
	header := []string{
		"application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.oci.image.manifest.v1+json",
		"application/vnd.docker.distribution.manifest.list.v2+json",
		"application/vnd.oci.image.index.v1+json",
		"application/vnd.docker.distribution.manifest.v1+json",
	}
	for _, h := range header {
		manifest, body, err := pullImageManifest(cli, repo, digest, h)
		if err == nil && manifest != nil {
			logging.Get().Info().Str("image", repo+"/"+digest).Str("header", h).Msg("pull image PullImageManifest")

			// 创建自定义的 DeserializedManifest，绕过 MediaType 检查
			deserializedManifest := &DeserializedManifest{
				Manifest:  *manifest,
				canonical: body,
			}

			return deserializedManifest, nil
		}
		logging.Get().Info().Str("image", repo+"/"+digest).Str("header", h).Msg("not pull image PullImageManifest")
	}
	return nil, fmt.Errorf("not found manifest")
}

func Url(cli *registry2.Registry, pathTemplate string, args ...interface{}) string {
	pathSuffix := fmt.Sprintf(pathTemplate, args...)
	url := fmt.Sprintf("%s%s", cli.URL, pathSuffix)
	return url
}

func ManifestV2Digest(m *DeserializedManifest) (string, error) {
	// caculate image digest
	data, err := m.MarshalJSON()
	if err != nil {
		return "", err
	}
	dig, _, err := SHA256(bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	return dig.String(), nil
}

func SHA256(r io.Reader) (Hash, int64, error) {
	hasher := sha256.New()
	n, err := io.Copy(hasher, r)
	if err != nil {
		return Hash{}, 0, err
	}
	return Hash{
		Algorithm: "sha256",
		Hex:       hex.EncodeToString(hasher.Sum(make([]byte, 0, hasher.Size()))),
	}, n, nil
}
