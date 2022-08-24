package component

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gobwas/glob"
	dockerparser "github.com/novln/docker-parser"
	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/security-rd/go-pkg/cryption/rsa"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/uuid"
)

type ImageRejectSrv interface {
	GetOverview(ctx context.Context, graph string) (*model.ImageRejectOverview, error)
	ListRejectRecord(ctx context.Context, search string, libraries []string, rejectReasons uint64, filter *model.Filter) ([]model.RejectRecord, int64, error)
	CreateImageWhitelist(ctx context.Context, name, library, tag, digest string) (*model.ImageWhitelist, error)
	ListImageWhitelist(ctx context.Context, search string, filter *model.Filter) ([]model.ImageWhitelist, int64, error)
	DeleteImageWhitelist(ctx context.Context, imageWhiteID int64) error

	DeletePolicy(ctx context.Context, id int64) error
	SearchRejectPolicy(ctx context.Context, library, globle string) ([]model.RejectPolicy, error)
	CreateSinglePolicy(ctx context.Context, policy model.RejectPolicy) error
	UpdateSinglePolicy(ctx context.Context, id int64, policy model.RejectPolicy) error
	CreateGlobalPolicy(ctx context.Context, policy model.GlobalRejectPolicy) error
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
	// rejectDbDal store.BaseImageDalInterface
}

func (s *ImageReject) UpdateSinglePolicy(ctx context.Context, id int64, policy model.RejectPolicy) error {
	// 漏洞阻断级别全是大写了，兼容前端
	policy.VulnLevel = strings.ToUpper(policy.VulnLevel)
	if err := checkRejectPolicy(policy); err != nil {
		return response.NewHttpError(http.StatusExpectationFailed, err)
	}
	if policy.Enable {
		// 一个仓库只能有一个生效策略，这里做一个限制
		policies, err := s.dbdal.SearchRejectPolicy(ctx, store.SearchRejectPolicyParam{Global: consts.FalseString})
		if err != nil {
			logging.GetLogger().Err(err).Msg("SearchRejectPolicy")
			return response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
		}
		for i := range policies {
			if !policies[i].Enable {
				continue
			}
			for j := range policy.Library {
				for k := range policies[i].Library {
					if policy.Library[j] == policies[i].Library[k] && policies[i].ID != id {
						return response.NewHttpError(http.StatusExpectationFailed, fmt.Errorf("library:%s 已设置生效策略", policy.Library[j]))
					}
				}
			}
		}
	}
	if len(policy.Library) == 0 {
		return response.NewHttpError(http.StatusExpectationFailed, fmt.Errorf("请指定策略的仓库"))
	}
	updater := rejectPolicyToUpdater(policy)
	if err := s.dbdal.UpdatePolicy(ctx, store.SearchRejectPolicyParam{ID: id, Global: consts.FalseString, UpdateRejectVulns: true, RejectVulns: policy.RejectVulns}, updater); err != nil {
		logging.GetLogger().Err(err).Msg("UpdateSinglePolicy")
		return response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("更新策略失败"))
	}
	return nil
}

func (s *ImageReject) CreateGlobalPolicy(ctx context.Context, global model.GlobalRejectPolicy) error {
	policies, err := s.dbdal.SearchRejectPolicy(ctx, store.SearchRejectPolicyParam{Global: consts.TrueString})
	if err != nil {
		return response.NewHttpError(http.StatusExpectationFailed, err)
	}
	if len(policies) == 0 {
		policy := model.RejectPolicy{
			CicdEnable:    global.CICDEnable,
			K8sEnable:     global.K8sEnable,
			Mode:          global.Mode,
			OnlineMonitor: global.OnlineMonitor,
			IsGlobal:      true,
		}

		policy.IsGlobal = true
		if _, err := s.dbdal.CreateRejectPolicy(ctx, policy); err != nil {
			logging.GetLogger().Err(err).Msg("CreateGlobalPolicy")
			return response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("创建策略失败"))
		}
	}

	// 全局策略对所有的策略都生效(但是gorm不允许更新整张表，所以这里分两次更新)
	updater := GlobalRejectPolicyToUpdater(global)

	if err := s.dbdal.UpdateGlobalPolicy(ctx, updater); err != nil {
		logging.GetLogger().Err(err).Msg("CreateGlobalPolicy")
		return response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("创建策略失败"))
	}

	return nil
}

func (s *ImageReject) SearchRejectPolicy(ctx context.Context, library, global string) ([]model.RejectPolicy, error) {
	policies, err := s.dbdal.SearchRejectPolicy(ctx, store.SearchRejectPolicyParam{
		Library: library,
		Global:  global,
	})
	if err != nil {
		logging.GetLogger().Err(err).Msg("SearchRejectPolicy")
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("查询策略失败"))
	}
	return policies, nil
}

func NewImageRejectSrc(dbdal store.ScannerDalInterface) *ImageReject {
	return &ImageReject{dbdal: dbdal}
}

func (s *ImageReject) DeletePolicy(ctx context.Context, id int64) error {
	if err := s.dbdal.DeletePolicy(ctx, id); err != nil {
		logging.GetLogger().Err(err).Msg("DeletePolicy")
		return response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("删除策略失败"))
	}
	return nil
}

func (s *ImageReject) GetOverview(ctx context.Context, graph string) (*model.ImageRejectOverview, error) {
	startAt := time.Date(time.Now().Year(), time.Now().Month(), time.Now().Day(), time.Now().Hour(), 0, 0, 0, time.UTC).Add(-23 * time.Hour)
	_, oneDayCount, err := s.dbdal.SearchRejectRecord(ctx, store.SearchRejectRecordParam{
		StartAt:   startAt,
		EndAt:     time.Now().UTC(),
		JustCount: true,
	}, model.EmptyFilterForTotalQuery())
	if err != nil {
		logging.GetLogger().Err(err).Msg("ImageReject.GetOverview.SearchRejectRecord")
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}

	startAt = time.Date(time.Now().Year(), time.Now().Month(), time.Now().Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, -6)
	_, sevenDayCount, err := s.dbdal.SearchRejectRecord(ctx, store.SearchRejectRecordParam{
		StartAt:   startAt,
		EndAt:     time.Now().UTC(),
		JustCount: true,
	}, model.EmptyFilterForTotalQuery())
	if err != nil {
		logging.GetLogger().Err(err).Msg("ImageReject.GetOverview.SearchRejectRecord")
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}

	tops, err := s.dbdal.OverviewReasonTopN(ctx, store.OverviewReasonParam{TopN: 5}, nil)
	if err != nil {
		return nil, err
	}
	res := &model.ImageRejectOverview{
		OneDayCount:   oneDayCount,
		SevenDayCount: sevenDayCount,
		Graphs:        nil,
		RejectTop5:    tops,
	}

	var graphs []store.IntervalDateGroup
	graphsRes := make([]int64, 0)
	var inters []time.Time

	switch graph {
	case consts.TwentyFourHour:
		graphs, err = s.dbdal.OverviewForInterval(ctx, 24, consts.IntervalHour)
		inters = GenerationInterval(24, consts.IntervalHour)
	case consts.SevenDay:
		graphs, err = s.dbdal.OverviewForInterval(ctx, 7, consts.IntervalDay)
		inters = GenerationInterval(7, consts.IntervalDay)
	default:
		graphs = make([]store.IntervalDateGroup, 0)
	}

	if err != nil {
		logging.GetLogger().Err(err).Msg("ImageReject.GetOverview.OverviewForInterval")
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}

	j := 0
	for i := 0; i < len(inters); i++ {
		if j >= len(graphs) {
			// 把剩余的补上
			k := len(inters) - len(graphsRes)
			for m := 0; m < k; m++ {
				graphsRes = append(graphsRes, 0)
			}
			break // 讲道理不会出现j>=len(graphs)的情况,这里这样写只是为了让程序具有健壮性
		}
		if inters[i] == graphs[j].IntervalDateTime {
			graphsRes = append(graphsRes, graphs[j].Count)
			j++
		} else {
			graphsRes = append(graphsRes, 0)
		}
	}

	res.Graphs = graphsRes
	return res, nil
}

func (s *ImageReject) ListRejectRecord(ctx context.Context, search string, libraries []string, rejectReasons uint64,
	filter *model.Filter) ([]model.RejectRecord, int64, error) {
	records, cnt, err := s.dbdal.SearchRejectRecord(ctx, store.SearchRejectRecordParam{Libraries: libraries, RejectReasons: rejectReasons, Search: search}, filter)
	if err != nil {
		logging.GetLogger().Err(err).Msg("ListRejectRecord")
		return nil, 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}
	return records, cnt, nil
}

func (s *ImageReject) CreateImageWhitelist(ctx context.Context, name, library, tag, digest string) (*model.ImageWhitelist, error) {
	// library必须在我们的注册仓库，镜像可以不在我们的数据库中(7-19确定方案),K8s的阻断记录是没有digest的，
	rys, _, err := s.dbdal.SearchRegistry(ctx, store.SearchRegistryParam{LibraryURL: library}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msg("CreateImageWhitelist")
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("创建白名单出错"))
	}
	if len(rys) == 0 {
		return nil, response.NewHttpError(http.StatusBadRequest, fmt.Errorf(fmt.Sprintf("该仓库：%s 不是注册仓库，不能加白", library)))
	}
	// 这里验证一下参数
	if name == "" {
		return nil, response.NewHttpError(http.StatusBadRequest, fmt.Errorf("no name"))
	}
	if library == "" {
		return nil, response.NewHttpError(http.StatusBadRequest, fmt.Errorf("no library"))
	}
	if tag == "" {
		return nil, response.NewHttpError(http.StatusBadRequest, fmt.Errorf("no tag"))
	}

	pre := model.ImageWhitelist{
		Library:      library,
		FullRepoName: name,
		Tag:          tag,
		Digest:       digest,
	}
	iw, err := s.dbdal.CreateImageWhitelist(ctx, pre)
	if err != nil {
		logging.GetLogger().Err(err).Interface("ImageWhitelist", pre).Msg("CreateImageWhitelist")
		if strings.Contains(err.Error(), consts.DuplicateKey) {
			// 如果是从k8s的阻断记录添加的白名单，这时是没有digest的，这里如果再加的话就要更新操作
			if digest != "" {
				whitelist, _, err := s.dbdal.SearchImageWhitelist(ctx, store.SearchImageWhitelistParam{Library: library, FullRepoName: name, Tag: tag}, nil)
				if err == nil && len(whitelist) > 0 && whitelist[0].Digest == "" {
					// 更新
					logging.GetLogger().WithContext(ctx).Infof("updating the digest of the whitelist")
					if err := s.dbdal.UpdateImageWhitelist(ctx,
						fmt.Sprintf("library = '%s' AND full_repo_name = '%s' AND tag = '%s'",
							library, name, tag), map[string]interface{}{"digest": digest}); err != nil {
						logging.GetLogger().Err(err).Msg("Error updating the digest of the whitelist")
						return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("更新白名单的Digest出错"))
					}
					return iw, nil
				}
			}
			return nil, response.NewHttpError(http.StatusBadRequest, errors.New("已存在，请不要重复添加"))
		}
		return nil, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("创建白名单出错"))
	}
	return iw, nil
}

func (s *ImageReject) ListImageWhitelist(ctx context.Context, search string, filter *model.Filter) ([]model.ImageWhitelist, int64, error) {
	lists, cnt, err := s.dbdal.SearchImageWhitelist(ctx, store.SearchImageWhitelistParam{SearchWord: search}, filter)
	if err != nil {
		logging.GetLogger().Err(err).Msg("ListImageWhitelist")
		return nil, 0, response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("查询镜像白名单出错"))
	}
	return lists, cnt, nil
}

func (s *ImageReject) DeleteImageWhitelist(ctx context.Context, imageWhiteID int64) error {
	err := s.dbdal.DeleteImageWhitelist(ctx, store.DeleteImageWhitelistParam{WhiteID: imageWhiteID})
	if err != nil {
		logging.GetLogger().Err(err).Msg("DeleteImageWhitelist")
		return response.NewHttpError(http.StatusInternalServerError, fmt.Errorf("删除镜像白名单出错"))
	}
	return nil
}

func (s *ImageReject) CreateSinglePolicy(ctx context.Context, policy model.RejectPolicy) error {
	policy.VulnLevel = strings.ToUpper(policy.VulnLevel)

	if err := checkRejectPolicy(policy); err != nil {
		return response.NewHttpError(http.StatusExpectationFailed, err)
	}

	for k := range policy.Library {
		if !strings.Contains(policy.Library[k], "http://") && !strings.Contains(policy.Library[k], "https://") {
			policy.Library[k] = "https://" + policy.Library[k]
		}
	}
	policy.IsGlobal = false
	// 一个仓库,可以建多个策略，但是只能有一个生效策略，这里做一个限制
	if policy.Enable {
		policies, err := s.dbdal.SearchRejectPolicy(ctx, store.SearchRejectPolicyParam{Global: consts.FalseString})
		if err != nil {
			logging.GetLogger().Err(err).Msg("SearchRejectPolicy")
			return response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
		}
		for i := range policies {
			if !policies[i].Enable {
				continue
			}
			for j := range policy.Library {
				for k := range policies[i].Library {
					if policy.Library[j] == policies[i].Library[k] {
						return response.NewHttpError(http.StatusExpectationFailed, fmt.Errorf("library:%s 已设置生效策略", policy.Library[j]))
					}
				}
			}
		}
	}

	if _, err := s.dbdal.CreateRejectPolicy(ctx, policy); err != nil {
		logging.GetLogger().Err(err).Msg("CreateSinglePolicy")
		return response.NewHttpError(http.StatusInternalServerError, fmt.Errorf(consts.StatusInternalServerErrorMsg))
	}
	return nil
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

func GenerationInterval(interval int, intervalType string) []time.Time {
	res := make([]time.Time, 0)
	if interval < 1 {
		return res
	}
	now := time.Now().UTC()
	switch intervalType {
	case consts.IntervalHour:
		for i := interval - 1; i >= 0; i-- {
			endAt := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), 0, 0, 0, time.UTC).Add(-time.Duration(i) * time.Hour).UTC()
			res = append(res, endAt)
		}
	case consts.IntervalDay:
		for i := interval - 1; i >= 0; i-- {
			endAt := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, -i).UTC()
			res = append(res, endAt)
		}
	}
	return res
}

func mergeRejectRecord(img model.ImageList, record []ReasonAndDetail) (*model.RejectRecord, error) {
	res := model.RejectRecord{
		Library:      img.Library,
		FullRepoName: img.FullRepoName,
		Tag:          img.Tags,
		RejectAt:     time.Now().UTC(),
		Digest:       img.Digest, // 这里把digest存起来，好排查问题
	}

	reasonMap := make(map[int64]int64)
	reasonDetailMap := make(map[string]int64)
	reasons := make([]int64, 0)
	reasonDetails := make([]string, 0)

	for i := range record {
		if reasonMap[record[i].RejectReason] < 1 {
			reasons = append(reasons, record[i].RejectReason)
			reasonMap[record[i].RejectReason]++
		}

		if reasonDetailMap[record[i].RejectDetail] < 1 {
			reasonDetails = append(reasonDetails, record[i].RejectDetail)
			reasonDetailMap[record[i].RejectDetail]++
		}
		// 对同一个仓库来说，只会设置一个阻断评分和阻断级别,所以这里可以直接在循环中更新值
		if record[i].VulnScore > 0 {
			res.VulnScore = record[i].VulnScore
		}
		if record[i].VulnLevel != "" {
			res.VulnLevel = record[i].VulnLevel
		}
	}
	reasonsDuplication := make(map[string]string)
	for _, r := range reasons {
		reasonsDuplication[strconv.Itoa(int(r))] = strconv.Itoa(int(r))
	}

	res.RejectDetail = strings.Join(reasonDetails, "|")
	res.RejectReason = reasons
	res.ReasonFlag = res.GenReasonFlag()
	return &res, nil
}
