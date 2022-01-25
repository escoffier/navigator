//go:build local
// +build local

// nolint
package component

import (
	"context"
	"testing"

	scanreport "gitlab.com/piccolo_su/vegeta/pkg/model/scan-report"

	"github.com/smartystreets/goconvey/convey"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/harbor"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

func TestCheckDetectImageForCICD(t *testing.T) {
	s := component.NewConScannerSrv(nil, Newmockregdal(), nil, nil, nil, nil, nil, nil, nil, nil)
	ctx := context.Background()
	expectDetails := []component.ReasonAndDetail{
		// {RejectReason: model.RejectNoLibrary, RejectDetail: model.GetRejectReason(model.LangZh)[model.RejectNoLibrary]},
		{RejectReason: model.RejectReasonHasMalicious, RejectDetail: model.GetRejectReason(model.LangZh)[model.RejectReasonHasMalicious]},
		{RejectReason: model.RejectReasonHasSensitiveFile, RejectDetail: model.GetRejectReason(model.LangZh)[model.RejectReasonHasSensitiveFile]},
		{RejectReason: model.RejectReasonVuluScore, RejectDetail: "漏洞综合评分：5，低于阻断分数：50"},
		{RejectReason: model.RejectReasonHasCustomizeVulu, RejectDetail: "包含自定义漏洞：自定义漏洞1，被阻断"},
		{RejectReason: model.RejectReasonHasCritical, RejectDetail: "包含漏洞：hello，评级：Critical，高于漏洞阻断评级：Negligible"},
		{RejectReason: model.RejectReasonWebshellScore, RejectDetail: "包含webshell文件：helloword，高于阻断评分：2"},
		{RejectReason: model.RejectReasonUntrustedBaseImage, RejectDetail: model.GetRejectReason(model.LangZh)[model.RejectReasonUntrustedBaseImage]},
	}
	expectHashs := []model.KVHashs{
		// {KVHash: model.KVHash{
		// 	EN: model.KeyValue{Key: model.GetRejectReason(model.LangEn)[model.RejectNoLibrary], Value: "image not in config registry,but image has add to the whitelist,unblocked"},
		// 	ZH: model.KeyValue{Key: model.GetRejectReason(model.LangZh)[model.RejectNoLibrary], Value: "来源镜像不在本地仓库，但镜像已加入白名单中，未被阻断"},
		// }},
		{KVHash: model.KVHash{
			EN: model.KeyValue{Key: model.GetRejectReason(model.LangEn)[model.RejectReasonHasMalicious], Value: "contains malicious file,but image has add to the whitelist,unblocked"},
			ZH: model.KeyValue{Key: model.GetRejectReason(model.LangZh)[model.RejectReasonHasMalicious], Value: "存在恶意文件，但镜像已加入白名单中，未被阻断"},
		}},
		{KVHash: model.KVHash{
			EN: model.KeyValue{Key: model.GetRejectReason(model.LangEn)[model.RejectReasonHasSensitiveFile], Value: "contain sensitive file,unblocked,just alert"},
			ZH: model.KeyValue{Key: model.GetRejectReason(model.LangZh)[model.RejectReasonHasSensitiveFile], Value: "存在敏感文件，但镜像已加入白名单中，未被阻断"},
		}},
		{KVHash: model.KVHash{
			EN: model.KeyValue{Key: model.GetRejectReason(model.LangEn)[model.RejectReasonVuluScore], Value: "vulnerability rate 5,Lower than:50,but image has add to the whitelist,unblocked"},
			ZH: model.KeyValue{Key: model.GetRejectReason(model.LangZh)[model.RejectReasonVuluScore], Value: "漏洞综合评分：5，低于阻断分数：50,但镜像已加入白名单中，未被阻断"},
		}},
		{KVHash: model.KVHash{
			EN: model.KeyValue{Key: model.GetRejectReason(model.LangEn)[model.RejectReasonHasCustomizeVulu], Value: "contain custom vulnerability:自定义漏洞1,but image has add to the whitelist,unblocked"},
			ZH: model.KeyValue{Key: model.GetRejectReason(model.LangZh)[model.RejectReasonHasCustomizeVulu], Value: "包含自定义漏洞：自定义漏洞1，但镜像已加入白名单中，未被阻断"},
		}},
		{KVHash: model.KVHash{
			EN: model.KeyValue{Key: model.GetRejectReason(model.LangEn)[model.RejectReasonHasCritical], Value: "include Vulnerability:hello Rate:Critical, more than:Negligible,but image has add to the whitelist,unblocked"},
			ZH: model.KeyValue{Key: model.GetRejectReason(model.LangZh)[model.RejectReasonHasCritical], Value: "包含漏洞：hello，评级：Critical，高于漏洞阻断评级：Negligible，但镜像已加入白名单中，未被阻断"},
		}},
		{KVHash: model.KVHash{
			EN: model.KeyValue{Key: model.GetRejectReason(model.LangEn)[model.RejectReasonWebshellScore], Value: "include websell file:helloword  more than:2,but image has add to the whitelist,unblocked"},
			ZH: model.KeyValue{Key: model.GetRejectReason(model.LangZh)[model.RejectReasonWebshellScore], Value: "包含webshell文件：helloword，高于阻断评分：2，但镜像已加入白名单中，未被阻断"},
		}},
		{KVHash: model.KVHash{
			EN: model.KeyValue{Key: model.GetRejectReason(model.LangEn)[model.RejectReasonUntrustedBaseImage], Value: "The application image is not built with a verified base image,but image has add to the whitelist,unblocked"},
			ZH: model.KeyValue{Key: model.GetRejectReason(model.LangZh)[model.RejectReasonUntrustedBaseImage], Value: "非基础镜像构建的应用镜像，但镜像已加入白名单中，未被阻断"},
		}},
	}

	convey.Convey("DetectImageForCICD", t, func() {
		polg := "https://registry.t-appagile.com"
		cicd, details, hashs, err := s.DetectImageForCICD(ctx, &model.ImageList{ID: 1, Library: polg})
		convey.ShouldEqual(cicd, true)
		convey.ShouldBeNil(err)
		// fmt.Println(details)

		convey.So(len(details), convey.ShouldEqual, len(expectDetails))
		convey.So(len(hashs), convey.ShouldEqual, len(expectHashs))

		for i := range details {
			convey.So(details[i].RejectReason, convey.ShouldEqual, expectDetails[i].RejectReason)
			convey.So(details[i].RejectDetail, convey.ShouldEqual, expectDetails[i].RejectDetail)
		}
		for i := range hashs {
			convey.So(hashs[i].KVHash.EN.Key, convey.ShouldEqual, expectHashs[i].KVHash.EN.Key)
			convey.So(hashs[i].KVHash.EN.Value, convey.ShouldEqual, expectHashs[i].KVHash.EN.Value)
			convey.So(hashs[i].KVHash.ZH.Key, convey.ShouldEqual, expectHashs[i].KVHash.ZH.Key)
			convey.So(hashs[i].KVHash.ZH.Value, convey.ShouldEqual, expectHashs[i].KVHash.ZH.Value)
		}
	})

}

type mockdal struct {
}

func (m *mockdal) CreateImage(ctx context.Context, data model.ImageList) error {
	panic("implement me")
}

func (m *mockdal) CreateTasks(ctx context.Context, tasks ...model.Task) error {
	panic("implement me")
}

func (m *mockdal) UpdateTask(ctx context.Context, task model.Task) error {
	panic("implement me")
}

func (m *mockdal) UpdateSubTask(ctx context.Context, subtask model.SubTask) error {
	panic("implement me")
}

func (m *mockdal) GetTasks(ctx context.Context, param store.SearchTaskParam, filter *model.Filter) ([]model.Task, int64, error) {
	panic("implement me")
}

func (m *mockdal) GetTotalTaskNum(ctx context.Context) (int64, error) {
	panic("implement me")
}

func (m *mockdal) UpdateTaskStatus(ctx context.Context, id int64, status uint8) error {
	panic("implement me")
}

func (m *mockdal) GetTaskList(ctx context.Context, limit, offset int) ([]model.Task, int64, error) {
	panic("implement me")
}

func (m *mockdal) GetSubTaskList(ctx context.Context, taskId int64, limit, offset int) ([]model.SubTask, int64, error) {
	panic("implement me")
}

func (m *mockdal) ScanReportCreate(ctx context.Context, report *scanreport.TensorScanReportTasks) error {
	panic("implement me")
}

func (m *mockdal) ScanReportDelete(ctx context.Context, id uint) error {
	panic("implement me")
}

func (m *mockdal) ScanReportUpdate(ctx context.Context, report *scanreport.TensorScanReportTasks) error {
	panic("implement me")
}

func (m *mockdal) ScanReportList(ctx context.Context, query string, limit, offset int) ([]scanreport.TensorScanReportTasks, int64, error) {
	panic("implement me")
}

func (m *mockdal) ScanReportDetail(ctx context.Context, id uint) (*scanreport.TensorScanReportTasks, error) {
	panic("implement me")
}

func (m *mockdal) ScanReportFilesList(ctx context.Context, scanReportId uint, limit, offset int) ([]scanreport.TensorScanReportSubTasks, int64, error) {
	panic("implement me")
}

func (m *mockdal) TrustedImagesMulti(ctx context.Context, digests []string) ([]model.TrustedImages, error) {
	data := []model.TrustedImages{
		{
			IsTrusted: 1,
		},
	}

	return data, nil
}

func (m *mockdal) TrustedImageCreat(ctx context.Context, trustedImage *model.TrustedImages) error {
	panic("implement me")
}

func (m *mockdal) ImageRsaCreate(ctx context.Context, data *model.ImageRsa) error {
	panic("implement me")
}

func (m *mockdal) ImageRsaUpdate(ctx context.Context, id int64, data *model.ImageRsa) error {
	panic("implement me")
}

func (m *mockdal) ImageRsaDetail(ctx context.Context, id int64) (*model.ImageRsa, error) {
	panic("implement me")
}

func (m *mockdal) ImageRsaDelete(ctx context.Context, id int64) error {
	panic("implement me")
}

func (m *mockdal) ImageRsaList(ctx context.Context, limit, offset int64) ([]model.ImageRsa, int64, error) {
	panic("implement me")
}

func (m *mockdal) ImageRsaQueryByPrivateKey(ctx context.Context, privateKey string) (*model.ImageRsa, error) {
	panic("implement me")
}

func (m *mockdal) SearchImageWithScan(ctx context.Context, param store.SearchImageWithScanParam, filter *model.Filter) ([]*model.ImageResponse, int64, error) {
	panic("implement me")
}

func (m *mockdal) UpdateGlobalPolicy(ctx context.Context, updater map[string]interface{}) error {
	panic("implement me")
}

type mockregdal struct {
}

func (m *mockregdal) SearchRegistry(ctx context.Context, param store.SearchRegistryParam, filter *model.Filter) ([]model.Registry, int64, error) {
	res := []model.Registry{model.Registry{Url: "https://registry.t-appagile.com"}}

	return res, 0, nil
}

func (m *mockregdal) CreateRegistry(ctx context.Context, reg model.Registry) (int64, error) {
	panic("implement me")
}

func (m *mockregdal) UpdateRegistry(ctx context.Context, param store.SearchRegistryParam, updater map[string]interface{}) error {
	panic("implement me")
}

func (m *mockregdal) DeleteRegistry(ctx context.Context, param store.SearchRegistryParam) error {
	panic("implement me")
}

func Newmockregdal() *mockregdal {
	return &mockregdal{}
}

func (m *mockdal) UpdatePolicy(ctx context.Context, param store.SearchRejectPolicyParam, updater map[string]interface{}) error {
	panic("implement me")
}

func newMockDAl() *mockdal {
	return &mockdal{}
}

func (m *mockdal) SearchImage(ctx context.Context, param store.SearchImageParam, filter *model.Filter) ([]model.ImageList, int64, error) {
	img := model.ImageList{
		ID: 1,
		// Url: "https://registry.t-appagile.com",
		// Layers: "hello", // 这里如果有值，那么两次查出来是同一个镜像，就不会报基础镜像不可信息的问题
	}
	return []model.ImageList{img}, 1, nil

}

func (m *mockdal) DeleteImage(ctx context.Context, param store.DeleteImageParam) error {
	panic("implement me")
}

func (m *mockdal) UpdateImage(ctx context.Context, where string, updater map[string]interface{}) error {
	panic("implement me")
}

func (m *mockdal) SearchScanLayer(ctx context.Context, param store.SearchScanLayerParam, filter *model.Filter) ([]model.ScanLayer, int64, error) {
	panic("implement me")
}

func (m *mockdal) SearchScanImage(ctx context.Context, param store.SearchScanImageParam, filter *model.Filter) ([]model.ScanImage, int64, error) {
	var si = model.ScanImage{
		ID:                1,
		ImageID:           1,
		RiskScore:         0.3,
		VulnScore:         3,
		SensitiveScore:    3,
		VirusScore:        3,
		WebshellScore:     3,
		VulnInfo:          []model.SingleScanDetail{},
		MaliciousInfoJSON: []byte("hello"),
		MaliciousInfo:     []model.Malicious{model.Malicious{VirusInfo: model.VirusInfo{}}},
		WebshellInfo:      []model.Webshell{{WebShellInfo: model.WebShellInfo{FileName: "helloword", Score: 3}}},
		SensitiveFile:     []model.Sensitive{model.Sensitive{Name: "hello"}},
		SensitiveFileJSON: []byte("hello"),
	}
	return []model.ScanImage{si}, 1, nil
}

func (m *mockdal) DeleteScanImage(ctx context.Context, param store.DeleteScanImageParam) error {
	panic("implement me")
}

func (m *mockdal) InsertScanImage(ctx context.Context, sis []model.ScanImage) (int64, error) {
	panic("implement me")
}

func (m *mockdal) InsertAdapterImageList(ctx context.Context, im model.ImageList) (int64, error) {
	panic("implement me")
}

func (m *mockdal) SearchRegistry(ctx context.Context, param store.SearchRegistryParam, filter *model.Filter) ([]model.Registry, int64, error) {
	panic("implement me")
}

func (m *mockdal) GetImageOverView(ctx context.Context, param store.GetImageOverViewParm) ([]store.ImageGroup, error) {
	panic("implement me")
}

func (m *mockdal) SearchRejectVuln(ctx context.Context, param store.SearchRejectRejectVulnParam) ([]model.RejectVuln, error) {
	panic("implement me")
}

func (m *mockdal) CreateRejectRecord(ctx context.Context, data model.RejectRecord) (*model.RejectRecord, error) {
	panic("implement me")
}

func (m *mockdal) CreateRejectPolicy(ctx context.Context, data model.RejectPolicy) (int64, error) {
	panic("implement me")
}

func (m *mockdal) GetScanimageFromImageList(ctx context.Context, imgId int64) (model.ScanImage, model.ImageList) {
	panic("implement me")
}

func (m *mockdal) GetTaskFromImageList(ctx context.Context, imgId int64, fromUrl string, auth string) (model.ScanTask, model.VirusScanTask, error) {
	panic("implement me")
}

func (m *mockdal) SearchScanAllStatus(ctx context.Context, fromType int64) harbor.ScanAllStatus {
	panic("implement me")
}

func (m *mockdal) GetVulnTotal(ctx context.Context) (int, error) {
	panic("implement me")
}

func (m *mockdal) GetVulnSeverityCount(ctx context.Context) (model.SeverityCount, error) {
	panic("implement me")
}

func (m *mockdal) GetVulnTop5(ctx context.Context) ([]model.ImageRiskScore, error) {
	panic("implement me")
}

func (m *mockdal) SearchVulns(ctx context.Context, searchWord string, filter *model.Filter) ([]model.VulnList, int, error) {
	panic("implement me")
}

func (m *mockdal) GetImagesFromVuln(ctx context.Context, name string) ([]model.VulnImageList, error) {
	panic("implement me")
}

func (m *mockdal) GetVulnDetails(ctx context.Context, name string) (model.VulnDetail, error) {
	panic("implement me")
}

func (m *mockdal) GetOnlineImage(ctx context.Context, parm store.GetOnlineImageParam) ([]store.OnlineImage, error) {
	panic("implement me")
}

func (m *mockdal) SetImageStatus(ctx context.Context, ids []int64, status string) error {
	panic("implement me")
}

func (m *mockdal) GetSimpleImageDetail(ctx context.Context, tag string, digest string, library string, fullRepoName string) model.SimpleImageDetail {
	panic("implement me")
}

func (m *mockdal) OverviewForInterval(ctx context.Context, interval int, intervalType string) ([]store.IntervalDateGroup, error) {
	panic("implement me")
}

func (m *mockdal) OverviewReasonTopN(ctx context.Context, param store.OverviewReasonParam, filter *model.Filter) ([]model.RejectReasonStatistic, error) {
	panic("implement me")
}

func (m *mockdal) SearchRejectRecord(ctx context.Context, param store.SearchRejectRecordParam, filter *model.Filter) ([]model.RejectRecord, int64, error) {
	panic("implement me")
}

func (m *mockdal) CreateImageWhitelist(ctx context.Context, data model.ImageWhitelist) (*model.ImageWhitelist, error) {
	panic("implement me")
}

func (m *mockdal) SearchImageWhitelist(ctx context.Context, param store.SearchImageWhitelistParam, filter *model.Filter) ([]model.ImageWhitelist, int64, error) {
	iw := model.ImageWhitelist{
		ID:      1,
		Library: "https://registry.t-appagile.com",
	}
	return []model.ImageWhitelist{iw}, 1, nil
}

func (m *mockdal) UpdateImageWhitelist(ctx context.Context, where string, update map[string]interface{}) error {
	panic("implement me")
}

func (m *mockdal) DeleteImageWhitelist(ctx context.Context, param store.DeleteImageWhitelistParam) error {
	panic("implement me")
}

func (m *mockdal) SearchRejectPolicy(ctx context.Context, param store.SearchRejectPolicyParam) ([]model.RejectPolicy, error) {
	po := model.RejectPolicy{
		ID:                  1,
		Name:                "hello",
		Library:             []string{"https://registry.t-appagile.com"},
		VulnScore:           50,
		VulnLevel:           model.SeverityNegligible,
		WebShellScore:       2,
		WebShellPolicy:      model.RejectPolicyReject,
		SensitiveFilePolicy: model.RejectPolicyReject,
		MaliciousPolicy:     model.RejectPolicyReject,
		BaseImagePolicy:     model.RejectPolicyReject,
		VulnPolicy:          model.RejectPolicyReject,
		CicdEnable:          true,
		K8sEnable:           true,
		RejectVulns: []model.RejectVuln{model.RejectVuln{
			ID:             1,
			RejectPolicyID: 1,
			Library:        "https://registry.t-appagile.com",
			Name:           "自定义漏洞1",
			RejectPolicy:   model.RejectPolicyReject,
		}},
		Mode:          model.RejectPolicySafeModel,
		OnlineMonitor: true,
		Enable:        true,
		IsGlobal:      false,
	}
	return []model.RejectPolicy{po}, nil
}

func (m *mockdal) GetPolicyConfig(ctx context.Context, getVuln bool) ([]model.RejectPolicy, error) {
	panic("implement me")
}

func (m *mockdal) AddSinglePolicy(ctx context.Context, policy model.RejectPolicy) (int64, error) {
	panic("implement me")
}

func (m *mockdal) DeletePolicy(ctx context.Context, policyID int64) error {
	panic("implement me")
}

func (m *mockdal) IsInRegistry(ctx context.Context, library string) bool {
	panic("implement me")
}

func (m *mockdal) GetK8sRejectImageList(ctx context.Context, image model.ImageList) *model.ImageList {
	panic("implement me")
}

func (m *mockdal) AddGlobalPolicyConfig(ctx context.Context, policy model.RejectPolicy) {
	panic("implement me")
}

func (m *mockdal) GetGlobalPolicyConfig(ctx context.Context) ([]model.RejectPolicy, error) {
	panic("implement me")
}
