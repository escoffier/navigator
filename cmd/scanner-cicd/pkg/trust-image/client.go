package trustimage

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/avast/retry-go"
	"github.com/docker/docker/client"
	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner-cicd/pkg/request"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/cryption/rsa"
)

type Client struct {
	private       *rsa.Private
	httpClient    *request.Request
	privateDigest string
	dockerClient  *client.Client
}

func NewClient(privatePath string, httpClient *request.Request) (*Client, error) {
	private, err := rsa.NewPrivateWithFile(privatePath)
	if err != nil {
		return nil, errors.Wrap(err, "创建私钥失败")
	}
	o, err := ioutil.ReadFile(privatePath)
	if err != nil {
		return nil, errors.Wrap(err, "打开私钥文件失败")
	}

	privateDigest, err := rsa.Sha256String(o)
	if err != nil {
		return nil, errors.Wrap(err, "获取私钥文件的sha256值失败")
	}

	dockerClient, err := client.NewClientWithOpts(client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, errors.Wrap(err, "初始化docker客户端失败")
	}

	return &Client{private: private, httpClient: httpClient, privateDigest: privateDigest, dockerClient: dockerClient}, nil
}

func (c *Client) Sign(ctx context.Context, image string, insecure bool, bufRegistryURL string) error {
	inspect, _, err := c.dockerClient.ImageInspectWithRaw(ctx, image)
	if err != nil {
		return errors.Wrapf(err, "获取镜像digest失败，image: %s", image)
	}

	bufRegistryURL = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(bufRegistryURL, "http://"), "https://"), "/")

	var digest string

	for _, v := range inspect.RepoDigests {
		if strings.Contains(v, bufRegistryURL) {
			digest = strings.Split(v, "@")[1]
			break
		}
	}

	if digest == "" {
		return errors.New("获取镜像digest为空")
	}

	logging.GetLogger().Debug().Msgf("digest: %s", digest)

	sign, err := c.private.Sign([]byte(strings.Join([]string{c.privateDigest, digest, image}, " ")))
	if err != nil {
		return errors.Wrap(err, "签名失败")
	}

	data := model.SignImageTrustedReq{
		Sign:          sign,
		Image:         image,
		Digest:        digest,
		PrivateDigest: c.privateDigest,
		Insecure:      insecure,
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		return errors.Wrap(err, "序列化签名数据失败")
	}

	err = util.RetryWithBackoff(ctx, func() error {
		return c.httpClient.Do("/api/openapi/scanner/imagereject/trustedImages/sign", http.MethodPost, bytes.NewBuffer(jsonData), nil)
	}, retry.Attempts(3))

	return err
}
