package deployment

import (
	"context"
	"regexp"
	"runtime/debug"
	"sort"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	"gitlab.com/piccolo_su/vegeta/pkg/util"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/detect"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagemeta"
	scani18 "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scanI18"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type DeployService interface {
	SearchDeployRecord(ctx context.Context, param imagesecModel.ImageSearchApiParam) ([]imagesecModel.DeployRecordView, int64, error)
	CreateDeployRecord(ctx context.Context, data *imagesecModel.DeployRecord) error
	SearchDeployWhiteImage(ctx context.Context, param imagesecModel.SearchDeployWhiteImageParam) ([]imagesecModel.DeployWhiteImage, int64, error)
	CreateDeployWhiteImage(ctx context.Context, data []*imagesecModel.DeployWhiteImage) error
	UpdateDeployWhiteImage(ctx context.Context, data *imagesecModel.DeployWhiteImage) error
	DeleteDeployWhiteImage(ctx context.Context, id int64) error
	CheckDeploy(ctx context.Context, param imagesecModel.DeployMonitorImage) bool
	DeployOverview(ctx context.Context, param imagesecModel.DeployDeployOverviewParam) ([]*imagesecModel.ActionOverview, error)
	DeployReasonTop5(ctx context.Context) ([]imagesecModel.ReasonOverview, error)
	DeployOverviewBlockTrend(ctx context.Context) (imagesecModel.DeployTrend, error)
}

type DeploySrv struct {
	ImagePolicyChecker detect.ImagePolicyChecker
	imageDal           imagesecStore.ImageMetaDal
	detectPolicyDal    imagesecStore.DetectPolicyDal
	scanResultDal      imagesecStore.ScanResultDal
	scanTaskDal        imagesecStore.ScanTaskDal
	ImageService       imagemeta.ImageService
	DeployRecordDal    imagesecStore.DeployDal
	BlockTrend         *DeployTrend
	ReasonTop5         *ReasonOverview
	Log                *scannerUtils.LogEvent
}

func NewDeploySrv(
	imagePolicyChecker detect.ImagePolicyChecker,
	imageDal imagesecStore.ImageMetaDal,
	detectPolicyDal imagesecStore.DetectPolicyDal,
	scanResultDal imagesecStore.ScanResultDal,
	scanTaskDal imagesecStore.ScanTaskDal,
	imageService imagemeta.ImageService,
	deployRecordDal imagesecStore.DeployDal,
) *DeploySrv {

	s := &DeploySrv{
		ImagePolicyChecker: imagePolicyChecker,
		imageDal:           imageDal,
		detectPolicyDal:    detectPolicyDal,
		scanResultDal:      scanResultDal,
		scanTaskDal:        scanTaskDal,
		ImageService:       imageService,
		DeployRecordDal:    deployRecordDal,
		BlockTrend:         NewDeployTrend(),
		ReasonTop5:         NewReasonOverview(5),
		Log: scannerUtils.NewLogEvent(
			scannerUtils.WithSubModule("DeploySrv"),
			scannerUtils.WithModule(consts.ModuleDeploy),
		),
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("module", "deployImage").Str("Stack", string(debug.Stack())).Msg("panic DeployOverview")
			}
		}()
		_, _ = s.DeployOverview(context.Background(), imagesecModel.DeployDeployOverviewParam{Graph: consts.DeployGraphDay7})
		_, _ = s.DeployOverview(context.Background(), imagesecModel.DeployDeployOverviewParam{Graph: consts.DeployGraphDay30})
		_, _ = s.DeployOverview(context.Background(), imagesecModel.DeployDeployOverviewParam{Graph: consts.DeployGraphHour24})
	}()

	return s
}

func (s *DeploySrv) CreateDeployRecord(ctx context.Context, data *imagesecModel.DeployRecord) error {
	err := s.DeployRecordDal.CreateDeployRecord(ctx, data)
	if err != nil {
		s.Log.Err(err).Msg("CreateDeployRecord")
		return scani18.CreatDeployRecord(err)
	}
	return nil
}

func (s *DeploySrv) SearchDeployRecord(ctx context.Context, param imagesecModel.ImageSearchApiParam) (
	[]imagesecModel.DeployRecordView, int64, error) {

	dalParam := param.ToImageDalParam()

	record, cnt, err := s.DeployRecordDal.SearchDeployRecord(ctx, dalParam)
	if err != nil {
		s.Log.Err(err).Msg("SearchDeployRecord")
		return nil, 0, scani18.SearchDeployRecord(err)
	}
	res := make([]imagesecModel.DeployRecordView, 0)
	// 获取漏洞统计这些信息
	if len(record) == 0 {
		return res, 0, nil
	}

	white, _, err := s.DeployRecordDal.SearchDeployWhiteImage(ctx, imagesecModel.SearchDeployWhiteImageParam{})
	if err != nil {
		return nil, 0, scani18.SearchDeployRecord(err)
	}
	wp := make(map[string]*regexp.Regexp)
	for i := range white {
		if white[i].ExpirationAt <= time.Now().UnixMilli() {
			continue
		}
		if compile, err := regexp.Compile(white[i].ImageName); err == nil {
			wp[white[i].ImageName] = compile
		}
	}

	for i := range record {
		da := &imagesecModel.ImageWithCorrelateData2{
			Image: imagesecModel.Image{Flag: record[i].Flag},
		}
		if len(record[i].Vuln) > 0 {
			vuln, _, err := s.scanResultDal.SearchVuln(ctx, imagesecModel.SearchVulnDalParam{VulnUniqueIds: record[i].Vuln})
			if err != nil {
				s.Log.Err(err).Msg("SearchDeployRecord SearchVuln")
				return nil, 0, scani18.SearchDeployRecord(err)
			}
			vulns := make([]*imagesecModel.VulnView, len(vuln))
			for j := range vuln {
				vulns[j] = vuln[j].GenVulnView()
			}
			da.Vuln = vulns
		}

		base := da.ToImageBaseResponse()
		rec := imagesecModel.GenDeployRecordView(&base, record[i])

		res = append(res, rec)
	}
	for i := range res {
		// 通过的不加白名单，再改的话就🐶了
		if res[i].Action == imagesecModel.DeployActionPass {
			res[i].InWhite = true
			continue
		}
		for _, re := range wp {
			if re.FindString(res[i].ImageName) != "" {
				res[i].InWhite = true
				break
			}
		}

	}

	return res, cnt, nil
}

func (s *DeploySrv) DeployOverview(ctx context.Context, param imagesecModel.DeployDeployOverviewParam) ([]*imagesecModel.ActionOverview, error) {
	res := make([]*imagesecModel.ActionOverview, 0)
	switch param.Graph {
	case consts.DeployGraphDay30:
		day30, err := s.deployOverviewDay30(ctx)
		if err != nil {
			s.Log.Err(err).Msg("DeployOverviewBlockTrend")
			return res, scani18.SearchDeployRecord(err)
		}
		res = day30

	case consts.DeployGraphHour24:
		hour24, err := s.deployOverviewHour24(ctx)
		if err != nil {
			s.Log.Err(err).Msg("DeployOverviewBlockTrend")
			return res, scani18.SearchDeployRecord(err)
		}
		res = hour24

	case consts.DeployGraphDay7:
		day7, err := s.deployOverviewDay7(ctx)
		if err != nil {
			s.Log.Err(err).Msg("DeployOverviewBlockTrend")
			return nil, scani18.SearchDeployRecord(err)
		}
		res = day7
	}

	return res, nil
}

func (s *DeploySrv) deployOverviewDay7(ctx context.Context) ([]*imagesecModel.ActionOverview, error) {
	res := make([]*imagesecModel.ActionOverview, 0)
	groups, err := s.DeployRecordDal.GroupRecordFlag(ctx, imagesecModel.GroupDeployFlagParam{
		Day7: consts.TrueString,
	})
	if err != nil {
		s.Log.Err(err).Msg("GroupRecordFlag")
		return res, scani18.SearchDeployRecord(err)
	}

	exit := make(map[int64]*imagesecModel.ActionOverview, 7)
	for i := 0; i < 7; i++ {
		day := util.DaySinceUnixEpoch(time.Now().UTC()) - int64(i)
		exit[day] = &imagesecModel.ActionOverview{
			TimeAt: util.UnixEpochAddDay(day),
			Group:  imagesecModel.ActionGroup{},
		}
	}
	var day7Block int64
	for i := 0; i < len(groups); i++ {
		gr := groups[i]
		if _, ok := exit[gr.Day]; !ok {
			ans := &imagesecModel.ActionOverview{
				TimeAt: util.UnixEpochAddDay(groups[i].Day),
				Group:  imagesecModel.ActionGroup{},
			}
			exit[gr.Day] = ans
		}

		ans := exit[gr.Day]

		ans.Total += groups[i].Count

		if util.ExistBit1(groups[i].Flag, imagesecModel.FlagImageDeployBlock) {
			day7Block += groups[i].Count
			ans.Group.Block += groups[i].Count
		}
		if util.ExistBit1(groups[i].Flag, imagesecModel.FlagImageDeployPassed) {
			ans.Group.Pass += groups[i].Count
		}
		if util.ExistBit1(groups[i].Flag, imagesecModel.FlagImageDeployAlarm) {
			ans.Group.Alarm += groups[i].Count
		}

		exit[gr.Day] = ans
	}
	s.BlockTrend.SetDay7(day7Block)

	for _, v := range exit {
		res = append(res, v)
	}
	sort.Sort(imagesecModel.ActionOverviews(res))
	for i := range res {
		res[i].AdaptTimeZone()
	}
	return res, nil
}

func (s *DeploySrv) deployOverviewDay30(ctx context.Context) ([]*imagesecModel.ActionOverview, error) {
	res := make([]*imagesecModel.ActionOverview, 0)
	groups, err := s.DeployRecordDal.GroupRecordFlag(ctx, imagesecModel.GroupDeployFlagParam{
		Day30: consts.TrueString,
	})
	if err != nil {
		s.Log.Err(err).Msg("GroupRecordFlag")
		return res, scani18.SearchDeployRecord(err)
	}

	exit := make(map[int64]*imagesecModel.ActionOverview, 30)
	for i := 0; i < 30; i++ {
		day := util.DaySinceUnixEpoch(time.Now()) - int64(i)
		exit[day] = &imagesecModel.ActionOverview{
			TimeAt: util.UnixEpochAddDay(day),
			Group:  imagesecModel.ActionGroup{},
		}
	}

	var day30Block int64
	for i := 0; i < len(groups); i++ {
		gr := groups[i]
		if _, ok := exit[gr.Day]; !ok {
			ans := &imagesecModel.ActionOverview{
				TimeAt: util.UnixEpochAddDay(groups[i].Day),
				Group:  imagesecModel.ActionGroup{},
			}
			exit[gr.Day] = ans
		}

		ans := exit[gr.Day]

		ans.Total += groups[i].Count

		if util.ExistBit1(groups[i].Flag, imagesecModel.FlagImageDeployBlock) {
			day30Block += groups[i].Count
			ans.Group.Block += groups[i].Count
		}
		if util.ExistBit1(groups[i].Flag, imagesecModel.FlagImageDeployPassed) {
			ans.Group.Pass += groups[i].Count
		}
		if util.ExistBit1(groups[i].Flag, imagesecModel.FlagImageDeployAlarm) {
			ans.Group.Alarm += groups[i].Count
		}

		exit[gr.Day] = ans
	}
	s.BlockTrend.SetDay30(day30Block)

	for _, v := range exit {
		res = append(res, v)
	}
	sort.Sort(imagesecModel.ActionOverviews(res))
	for i := range res {
		res[i].AdaptTimeZone()
	}

	return res, nil
}

// DeployOverview 展示异常记录,现在只是为了应标，后期优化
func (s *DeploySrv) deployOverviewHour24(ctx context.Context) ([]*imagesecModel.ActionOverview, error) {
	res := make([]*imagesecModel.ActionOverview, 0)
	groups, err := s.DeployRecordDal.GroupRecordFlag(ctx, imagesecModel.GroupDeployFlagParam{
		Hour24: consts.TrueString,
	})
	if err != nil {
		s.Log.Err(err).Msg("GroupRecordFlag")
		return res, scani18.SearchDeployRecord(err)
	}

	exit := make(map[int64]*imagesecModel.ActionOverview, 24)
	for i := 0; i < 24; i++ {
		day := util.HourSinceUnixEpoch(time.Now()) - int64(i)
		exit[day] = &imagesecModel.ActionOverview{
			TimeAt: util.UnixEpochAddHour(day),
			Group:  imagesecModel.ActionGroup{},
		}
	}

	var hour24Block int64
	for i := 0; i < len(groups); i++ {
		gr := groups[i]
		if _, ok := exit[gr.Hour]; !ok {
			ans := &imagesecModel.ActionOverview{
				TimeAt: util.UnixEpochAddHour(groups[i].Hour),
				Group:  imagesecModel.ActionGroup{},
			}
			exit[gr.Hour] = ans
		}

		ans := exit[gr.Hour]

		ans.Total += groups[i].Count

		if util.ExistBit1(groups[i].Flag, imagesecModel.FlagImageDeployBlock) {
			hour24Block += groups[i].Count
			ans.Group.Block += groups[i].Count
		}
		if util.ExistBit1(groups[i].Flag, imagesecModel.FlagImageDeployPassed) {
			ans.Group.Pass += groups[i].Count
		}
		if util.ExistBit1(groups[i].Flag, imagesecModel.FlagImageDeployAlarm) {
			ans.Group.Alarm += groups[i].Count
		}

		exit[gr.Hour] = ans
	}
	s.BlockTrend.SetHour24(hour24Block)

	for _, v := range exit {
		res = append(res, v)
	}
	sort.Sort(imagesecModel.ActionOverviews(res))
	return res, nil
}

// 需要优化
func (s *DeploySrv) DeployOverviewBlockTrend(ctx context.Context) (imagesecModel.DeployTrend, error) {
	return s.BlockTrend.Get(), nil
}

func (s *DeploySrv) DeployReasonTop5(ctx context.Context) ([]imagesecModel.ReasonOverview, error) {

	var res []imagesecModel.ReasonOverview // 只需要返回reason top5即可
	groups, err := s.DeployRecordDal.GroupRecordFlag(ctx, imagesecModel.GroupDeployFlagParam{
		Reason: consts.TrueString,
	})

	if err != nil {
		s.Log.Err(err).Msg("GroupRecordFlag")
		return res, scani18.SearchDeployRecord(err)
	}
	// 先查全部
	s.ReasonTop5.Set(groups)
	return s.ReasonTop5.Get(), nil
}
