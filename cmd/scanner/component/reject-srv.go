package component

import (
	"context"
	"fmt"
	"strings"

	"github.com/gobwas/glob"
	dockerparser "github.com/novln/docker-parser"
	"github.com/pkg/errors"
	"gitlab.com/security-rd/go-pkg/cryption/rsa"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/uuid"
)

type ImageRejectSrv interface {

	// RSAGenerate 生成rsa key pair
	RSAGenerate(ctx context.Context, req *model.ImageRsa) ([]byte, error)
	// RSAUpdate 更新 rsa 处理规则
	RSAUpdate(ctx context.Context, id int64, req *model.ImageRsa) error
	// RSADetail 获取rsa及其规则详情
	RSADetail(ctx context.Context, id int64) (*model.ImageRsa, error)
	// RSADelete 删除rsa规则
	RSADelete(ctx context.Context, id int64) error
	// RSAList 暂时rsa规则简要信息
	RSAList(ctx context.Context, param RSAListParam, filter *model.Filter) ([]model.ImageRsa, int64, error)
	// SignImageTrusted 将一个镜像标识为可信
	SignImageTrusted(ctx context.Context, req *model.SignImageTrustedReq) error
}

type RSAListParam struct {
	Name string `json:"name"`
}

type ImageReject struct {
	dbdal store.ScannerDalInterface
}

func (s *ImageReject) RSAGenerate(ctx context.Context, req *model.ImageRsa) ([]byte, error) {
	// check req
	if err := req.Check(); err != nil {
		logging.GetLogger().Err(err).Msg("参数检查失败")
		return nil, err
	}

	keyPair, err := rsa.GenerateRSA(ctx)
	if err != nil {
		logging.GetLogger().Err(err).Msg("crate rsa key pair failed")
		return nil, err
	}

	privateKeyHash, err := rsa.Sha256String(keyPair.PrivateKey)
	if err != nil {
		logging.GetLogger().Err(err).Msg("get rsa private key sha256 digest failed")
		return nil, err
	}

	req.PrivateKeyDigest = privateKeyHash
	req.PublicKey = string(keyPair.PublicKey)
	req.RsaId = fmt.Sprintf("KEY-%s", uuid.GenerateRandomID()[:9])

	err = s.dbdal.ImageRsaCreate(ctx, req) // 保存数据库
	if err != nil {
		logging.GetLogger().Err(err).Msgf("密钥保存失败, name: %s, rsa_id: %s", req.Name, req.RsaId)
		return nil, errors.Wrapf(err, "密钥保存失败, name: %s, rsa_id: %s", req.Name, req.RsaId)
	}

	return keyPair.PrivateKey, nil
}

func (s *ImageReject) RSAUpdate(ctx context.Context, id int64, req *model.ImageRsa) error {
	if err := req.Check(); err != nil {
		logging.GetLogger().Err(err).Msg("参数检查失败")
		return err
	}

	err := s.dbdal.ImageRsaUpdate(ctx, id, req)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("%s密钥更新失败", req.Name)
		return errors.Wrapf(err, "%s密钥更新失败", req.Name)
	}

	return nil
}

func (s *ImageReject) RSADetail(ctx context.Context, id int64) (*model.ImageRsa, error) {
	data, err := s.dbdal.ImageRsaDetail(ctx, id)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("id<%d>密钥查询失败", id)
		return nil, err
	}

	return data, nil
}

func (s *ImageReject) RSADelete(ctx context.Context, id int64) error {
	err := s.dbdal.ImageRsaDelete(ctx, id)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("id<%d>密钥删除失败", id)
		return err
	}
	return nil
}

func (s *ImageReject) RSAList(ctx context.Context, param RSAListParam, filter *model.Filter) ([]model.ImageRsa, int64, error) {
	r, c, err := s.dbdal.ImageRsaList(ctx, store.RSAListParam{Name: param.Name}, filter)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("分页查询失败")
		return nil, 0, err
	}

	return r, c, nil
}

func (s *ImageReject) SignImageTrusted(ctx context.Context, req *model.SignImageTrustedReq) error {

	imageName, err := dockerparser.Parse(req.Image)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("镜像名<%s>解析失败", req.Image)
		return errors.Wrapf(err, "镜像名<%s>解析失败", req.Image)
	}

	// 通过privateDigest获取到对应的publicKey
	pub, err := s.dbdal.ImageRsaQueryByPrivateKey(ctx, req.PrivateDigest)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("公钥查询失败")
		return err
	}

	if pub.Registry == "" {
		logging.GetLogger().Error().Msgf("此密钥暂未指定使用仓库")
		return errors.New("此密钥暂未指定使用仓库")
	}

	var registry = imageName.Registry()
	if req.Insecure {
		registry = "http://" + registry
	} else {
		registry = "https://" + registry
	}

	if pub.Registry != registry {
		logging.GetLogger().Error().Msgf("registry不匹配, need: <%s>, actual: <%s>", pub.Registry, registry)
		return fmt.Errorf("registry不匹配, need: <%s>, actual: <%s>", pub.Registry, registry)
	}

	if pub.MatchRule == "" {
		logging.GetLogger().Error().Msgf("此密钥暂未指定匹配规则")
		return errors.New("此密钥暂未指定匹配规则")
	}

	g, err := glob.Compile(pub.MatchRule, '/')
	if err != nil {
		logging.GetLogger().Err(err).Msgf("匹配规则编译失败, 规则: %s", pub.MatchRule)
		return errors.Wrapf(err, "匹配规则编译失败, 规则: %s", pub.MatchRule)
	}

	// 镜像名匹配规则
	// 这里需要判断前面是否有 "/"的情况
	// 比如规则是/a/b:v1, 但是镜像名为a/b:v1, 这时应该匹配成功
	if !(g.Match(imageName.Name()) || g.Match("/"+imageName.Name())) {
		logging.GetLogger().Error().Msgf("镜像名不符合正则匹配规则, 镜像名:%s, 规则：%s", imageName.Name(), pub.MatchRule)
		return fmt.Errorf("镜像名不符合正则匹配规则, 镜像名:%s, 规则：%s", imageName.Name(), pub.MatchRule)
	}

	pubKey, err := rsa.NewPublicWithBytes([]byte(pub.PublicKey))
	if err != nil {
		logging.GetLogger().Err(err).Msgf("生成公钥对象失败")
		return err
	}

	// 签名认证
	err = pubKey.
		VerifySign([]byte(strings.Join([]string{req.PrivateDigest, req.Digest, req.Image}, " ")), req.Sign)

	if err != nil {
		logging.GetLogger().Err(err).Msgf("签名认证失败")
		return err
	}

	// 保存认证结果
	data := &model.TrustedImages{
		Digest:    req.Digest,
		IsTrusted: 1,
	}
	err = s.dbdal.TrustedImageCreat(ctx, data)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("保存可信镜像<%s>失败", req.Digest)
		// 如果是唯一键冲突的话，则也说明插入成功
		if !strings.Contains(strings.ToLower(err.Error()), "duplicate") {
			return errors.Wrap(err, "保存可信镜像信息失败")
		}
	}

	return nil
}

func NewImageRejectSrc(dbdal store.ScannerDalInterface) *ImageReject {
	return &ImageReject{dbdal: dbdal}
}
