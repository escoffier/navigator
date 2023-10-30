package imagesec

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"
	"scm.tensorsecurity.cn/tensorsecurity-rd/fanal/types"

	imagesecTypes "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

// 镜像元信息
type Image struct {
	ID               int64                 `gorm:"primary_key;AUTO_INCREMENT" json:"id" `
	UniqueID         uint64                `gorm:"column:unique_id" json:"uniqueID,string"`     // 生成的ID，写入关联数据时就不用事务
	ImageFromType    string                `gorm:"column:image_from_type" json:"imageFromType"` // CI,NODE,LIB 这三类
	ImageID          string                `gorm:"column:image_id" json:"imageID"`              // 对于节点镜像，部分镜像是没有digest这个信息的
	Host             string                `gorm:"column:host" json:"host"`
	Repo             string                `gorm:"column:repo" json:"repo"`
	Tag              string                `gorm:"column:tag" json:"tag"`
	ImageName        string                `gorm:"column:image_name" json:"imageName"` // 主要用于搜索
	Digest           string                `gorm:"column:digest" json:"digest"`
	OS               types.OS              `gorm:"-" json:"os"` // 为啥不用 ImageOS :为了兼容老数据,返回数据为啥要定义新结构体:因为 trivy 的Eosl 可能不序列化
	OSJson           string                `gorm:"column:os" json:"-"`
	Size             int64                 `gorm:"column:size" json:"size"` // 单位：byte
	LayerJSON        string                `gorm:"column:layer" json:"-"`
	LayerStr         string                `gorm:"column:layer_str" json:"layerStr"` // 层级信息转 uint32，用|分隔
	Layer            []imagesecTypes.Layer `gorm:"-" json:"layer"`
	BuildAt          int64                 `gorm:"column:build_at" json:"buildAt"` // build时间
	User             string                `gorm:"column:user" json:"user"`        // 启动用户
	Flag             uint64                `gorm:"column:flag" json:"flag,string"` // 最近一次镜像元信息
	ImageUUID        uint32                `gorm:"column:image_uuid" json:"imageUUID"`
	RegID            int64                 `gorm:"column:reg_id" json:"regID"`
	NodeID           uint64                `gorm:"column:node_id" json:"nodeID,string"`
	Project          string                `gorm:"column:project" json:"project"`                           // 仓库层级
	Heartbeat        int64                 `gorm:"column:heartbeat" json:"heartbeat"`                       // 上一次上报的心跳 milliseconds
	PullCount        int64                 `gorm:"pull_count" json:"pullCount"`                             // 镜像的下载时间
	PolicyUniqueJson string                `gorm:"column:policy_unique_id" json:"-"`                        // 主要是为了策略查询
	CreatedAt        int64                 `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt        int64                 `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
}

type RootBoot struct {
	User         string       `json:"user"`
	IsRoot       bool         `json:"isRoot"`
	UniqueID     uint64       `json:"uniqueID,string"`
	PolicyDetect PolicyDetect `json:"policyDetect"` // 对各个策略的检测结果
}

type TrustedImage struct {
	Trusted      bool         `json:"trusted"` // 是否可信
	Digest       string       `json:"digest"`
	UniqueID     uint64       `json:"uniqueID,string"`
	PolicyDetect PolicyDetect `json:"policyDetect"` // 对各个策略的检测结果
}

type ImageInReg struct {
	RegIds       []int64      `json:"regID"` // 是否可信
	UniqueID     uint64       `json:"uniqueID,string"`
	PolicyDetect PolicyDetect `json:"policyDetect"` // 对各个策略的检测结果
}

const (
	DockerHost = "index.docker.io"
)

type Layers []imagesecTypes.Layer

func (vi Layers) Len() int {
	return len(vi)
}

func (vi Layers) Less(i, j int) bool {
	return vi[i].Created < vi[j].Created
}

func (vi Layers) Swap(i, j int) {
	vi[i], vi[j] = vi[j], vi[i]
}

func (vi *Image) SortLayer() {
	lay := vi.Layer

	sort.Sort(Layers(lay))
	vi.Layer = lay
}

func (vi *Image) BootRoot() bool {
	if vi == nil {
		return false
	}
	return vi.User == "" || vi.User == BootRootUser
}

func (vi *Image) Same(after *Image) bool {
	return vi.UniqueID == after.UniqueID && vi.Digest == after.Digest
}

func (vi *Image) GetImageName() string {
	if vi == nil {
		return ""
	}
	if vi.ImageName != "" {
		return vi.ImageName
	}

	imageName := vi.Repo + ":" + vi.Tag
	if vi.Host != "" && !strings.Contains(vi.Host, DockerHost) {
		imageName = vi.Host + "/" + imageName
	}

	return imageName
}

func (vi *Image) GetDockerPullImageName() string {
	if vi == nil {
		return ""
	}

	imageName := vi.Repo + ":" + vi.Tag
	if vi.Host != "" && !strings.Contains(vi.Host, DockerHost) {
		imageName = vi.Host + "/" + imageName
	}

	imageName = strings.ReplaceAll(imageName, "http://", "")
	imageName = strings.ReplaceAll(imageName, "https://", "")

	return imageName
}

func (vi *Image) Deserialize() {
	vi.Layer = make([]imagesecTypes.Layer, 0)
	layer := make([]imagesecTypes.Layer, 0)
	if vi.LayerJSON != "" {
		if err := json.Unmarshal([]byte(vi.LayerJSON), &layer); err == nil {
			vi.Layer = layer
		}
	}
	if vi.OSJson != "" {
		scanOS := types.OS{}
		if err := json.Unmarshal([]byte(vi.OSJson), &scanOS); err == nil {
			vi.OS = scanOS
		}
	}

	if strings.Contains(vi.Host, DockerHost) {
		vi.Host = ""
		vi.Repo = strings.Replace(vi.Repo, "library/", "", 1)
	}

	// 节点镜像的层是秒
	for i := range vi.Layer {
		if vi.Layer[i].Created < (time.Now().UnixMilli())/100 {
			vi.Layer[i].Created = vi.Layer[i].Created * 1000
		}
	}
}

func (vi *Image) Serialize() {

	if vi.Flag <= 0 {
		vi.Flag = vi.GenDefaultFlag()
	}
	// 节点镜像的层是秒
	for i := range vi.Layer {
		if vi.Layer[i].Created < (time.Now().UnixMilli())/100 {
			vi.Layer[i].Created = vi.Layer[i].Created * 1000
		}
	}

	if byt, err := json.Marshal(vi.Layer); err == nil {
		vi.LayerJSON = string(byt)
	}

	if bys, err := json.Marshal(vi.OS); err == nil {
		vi.OSJson = string(bys)
	}
	// 本身属性
	if vi.User == BootRootUser || vi.User == "" {
		vi.Flag = util.SetBit1(vi.Flag, FlagImageExceptionBoot)
	}

	vi.ImageName = vi.GetImageName()

	vi.UniqueID = vi.GenUniqueID()
	vi.ImageUUID = vi.GenUUID()
	vi.LayerStr = vi.GenLayerStr()
}

func (vi *Image) DeepCopy() *Image {
	bts, _ := json.Marshal(vi)
	after := &Image{}

	_ = json.Unmarshal(bts, after)
	return after
}

func (vi *Image) GenDefaultFlag() uint64 {
	var flag uint64
	flag = util.SetBit1(flag, FlagImageSafeUnknown)
	flag = util.SetBit1(flag, FlagImageUnTrusted)
	flag = util.SetBit1(flag, FlagImageNotOnline)
	flag = util.SetBit1(flag, FlagAppImage)
	vi.Flag = flag
	return flag
}

type ImageLayer struct {
	Digest        string   `json:"digest"`
	CreatedAt     int64    `json:"createdAt"`
	CreatedBy     string   `json:"createdBy"`
	Vuln          []string `json:"vuln"`
	Pkg           []string `json:"pkg"`
	Malware       []string `json:"malware"`
	SensitiveFile []string `json:"sensitiveFile"`
	Webshell      []string `json:"webshell"`
	ImageID       int64    `json:"imageID"`
	ImageUniqueID int64    `json:"imageUniqueID"`
}

func (vi *Image) Check() error {
	if vi == nil {
		return fmt.Errorf("model is nil")
	}
	if err := ImageFromType(vi.ImageFromType).Check(); err != nil {
		return err
	}
	if vi.ImageName == "" {
		vi.ImageName = vi.GetImageName()
	}
	if vi.Repo == "" {
		return fmt.Errorf("image not get Repo")
	}
	if vi.Host == "" {
		return fmt.Errorf("image not get host")
	}
	if vi.Tag == "" {
		return fmt.Errorf("image not get Tag")
	}
	if vi.Digest == "" {
		return fmt.Errorf("image not get Digest")
	}
	if vi.ImageFromType == ImageFromRegistry && vi.RegID <= 0 {
		return fmt.Errorf("image not get RegID")
	}
	if vi.ImageFromType == ImageFromNode && vi.NodeID <= 0 {
		return fmt.Errorf("image not get NodeID")
	}
	if vi.UniqueID <= 0 {
		vi.UniqueID = vi.GenUniqueID()
	}
	if vi.UniqueID <= 0 {
		return fmt.Errorf("image not get uniqueID")
	}
	return nil
}

func (vi *Image) GenUniqueID() uint64 {
	if vi == nil {
		return 0
	}
	var uid uint64
	switch vi.ImageFromType {
	case ImageFromCI:
		return 0 // ci
	case ImageFromRegistry:
		uid = util.GenerateUUID64(fmt.Sprintf("%d-%s-%s-%s", vi.RegID, vi.Repo, vi.Tag, vi.ImageFromType))
	case ImageFromNode:
		uid = util.GenerateUUID64(fmt.Sprintf("%d-%s-%s-%s-%s", vi.NodeID, vi.ImageName, vi.Digest, vi.ImageID, vi.ImageFromType))
	case ImageFromDeploy:
		uid = util.GenerateUUID64(fmt.Sprintf("%s-%s-%s", vi.ImageName, vi.Digest, vi.ImageFromType))
	}
	vi.UniqueID = uid
	return uid
}

func (vi *Image) GenUUID() uint32 {
	imageName := vi.GetImageName()
	imageName = strings.ReplaceAll(imageName, "https://", "")
	imageName = strings.ReplaceAll(imageName, "http://", "")
	imageName = fmt.Sprintf("%s@%s", imageName, vi.Digest)
	return util.GenerateUUID(imageName)
}

func (vi *Image) GenLayerStr() string {
	res := make([]string, 0)

	for i := range vi.Layer {
		uuid := util.GenerateUUID(vi.Layer[i].Digest)
		res = append(res, fmt.Sprintf("%d", uuid))
	}
	return strings.Join(res, ",")
}

func (vi *Image) GetImageOs() string {
	osString := fmt.Sprintf("%s:%s", vi.OS.Family, vi.OS.Name)
	if osString == ":" {
		return ""
	}
	return osString
}

func (vi *Image) TableName() string {
	if vi == nil {
		return ""
	}
	return "ivan_scan_image_meta"
}

// 镜像详情中问题统计
type SecurityStatistic struct {
	ImageCount  int64               `json:"imageCount"`
	OnlineCount int64               `json:"onlineCount"`
	Total       SecurityIssueStatic `json:"total"`
	Online      SecurityIssueStatic `json:"online"`
	Risk        SecurityIssueStatic `json:"risk"` // 单个镜像统计
}

func (vi *SecurityStatistic) DeepCopy() SecurityStatistic {
	if vi == nil {
		return SecurityStatistic{}
	}

	res := SecurityStatistic{
		ImageCount:  vi.ImageCount,
		OnlineCount: vi.OnlineCount,
		Total:       vi.Total.DeepCopy(),
		Online:      vi.Online.DeepCopy(),
		Risk:        vi.Risk.DeepCopy(),
	}
	return res

}

type SecurityOverview struct {
	Vuln          string `json:"exceptionVuln"`
	Malware       string `json:"exceptionMalware"`
	Sensitive     string `json:"exceptionSensitive"`
	Webshell      string `json:"exceptionWebshell"`
	Env           string `json:"exceptionEnv"`
	Pkg           string `json:"exceptionPKG"`
	License       string `json:"exceptionLicense"`
	ExceptionBoot string `json:"exceptionBoot"`
	PkgLicense    string `json:"exceptionPkgLicense"`
	HasFixedVuln  string `json:"hasFixedVuln"`
	NotInRegistry string `json:"notInRegistry"` // 不在仓库中
	Untrusted     string `json:"untrusted"`
}

// 应前端的要求统一,所以json tag 不一致
type SecurityIssueStatic struct {
	Vuln          int64 `json:"exceptionVuln"`
	Malware       int64 `json:"exceptionMalware"`
	Sensitive     int64 `json:"exceptionSensitive"`
	Webshell      int64 `json:"exceptionWebshell"`
	Env           int64 `json:"exceptionEnv"`
	Pkg           int64 `json:"exceptionPKG"`
	License       int64 `json:"exceptionLicense"`
	ExceptionBoot int64 `json:"exceptionBoot"`
	PkgLicense    int64 `json:"exceptionPkgLicense"`
	// HasFixedVuln     int64 `json:"hasFixedVuln"` // 属于镜像属性，不再属于安全问题
	NotInRegistry    int64 `json:"notInRegistry"` // 不在仓库中
	Untrusted        int64 `json:"untrusted"`
	NotExitBaseImage int64 `json:"notExitBaseImage"`
}

func (vi *SecurityIssueStatic) DeepCopy() SecurityIssueStatic {
	if vi == nil {
		return SecurityIssueStatic{}
	}
	return SecurityIssueStatic{
		Vuln:          vi.Vuln,
		Malware:       vi.Malware,
		Sensitive:     vi.Sensitive,
		Webshell:      vi.Webshell,
		Env:           vi.Env,
		Pkg:           vi.Pkg,
		License:       vi.License,
		ExceptionBoot: vi.ExceptionBoot,
		PkgLicense:    vi.PkgLicense,
		// HasFixedVuln:  vi.HasFixedVuln,
		NotInRegistry: vi.NotInRegistry,
		Untrusted:     vi.Untrusted,
	}
}

type ImageSuggest struct {
	Title string   `json:"title"`
	Data  []string `json:"data"`
}

type ImagePrepareData struct {
	RegGroupProject   []GroupProject
	NodeGroupProject  []GroupProject
	RegImageOverView  SecurityStatistic
	NodeImageOverView SecurityStatistic
}

func (vi *ImagePrepareData) DeepCopy() *ImagePrepareData {
	return &ImagePrepareData{
		RegGroupProject:   append([]GroupProject{}, vi.RegGroupProject...),
		NodeGroupProject:  append([]GroupProject{}, vi.NodeGroupProject...),
		NodeImageOverView: vi.NodeImageOverView.DeepCopy(),
		RegImageOverView:  vi.RegImageOverView.DeepCopy(),
	}
}

type BaseImageRule struct {
	ID        int64  `gorm:"primary_key;AUTO_INCREMENT" json:"id" `
	UniqueID  uint64 `gorm:"column:unique_id" json:"uniqueID,string"` // 生成的ID，写入关联数据时就不用事务
	Name      string `gorm:"column:name" json:"name"`
	Updater   string `gorm:"column:updater" json:"updater"`
	CreatedAt int64  `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt int64  `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
}

type CacheInfo struct {
	ID               int64             `gorm:"primary_key;AUTO_INCREMENT" json:"id" `
	DataType         string            `gorm:"column:data_type" json:"dataType"`
	Data             string            `gorm:"column:data" json:"data"`
	ImagePrepareData *ImagePrepareData `gorm:"-" json:"imagePrepareData"`
	VulnOverview     *VulnOverview     `gorm:"-" json:"vulnOverview"`
	CreatedAt        int64             `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt        int64             `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
}

func (vi *CacheInfo) Serialize() {
	if vi.DataType == CacheTypeImagePrepare {
		bys, err := json.Marshal(vi.ImagePrepareData)
		if err != nil {
			logging.Get().Err(err).Str("module", "imageMeta").Msg("Marshal")
		} else {
			vi.Data = string(bys)
		}
	}

	if vi.DataType == CacheTypVulnOverview {
		bys, err := json.Marshal(vi.VulnOverview)
		if err != nil {
			logging.Get().Err(err).Str("module", "imageMeta").Msg("Marshal")
		} else {
			vi.Data = string(bys)
		}
	}
}

func (vi *CacheInfo) Deserializer() {
	if vi.DataType == CacheTypeImagePrepare {
		pre := &ImagePrepareData{}
		err := json.Unmarshal([]byte(vi.Data), pre)
		if err != nil {
			logging.Get().Err(err).Str("module", "imageMeta").Msg("Unmarshal")
		} else {
			vi.ImagePrepareData = pre
		}
	}

	if vi.DataType == CacheTypVulnOverview {
		pre := &VulnOverview{}
		err := json.Unmarshal([]byte(vi.Data), pre)
		if err != nil {
			logging.Get().Err(err).Str("module", "imageMeta").Msg("Unmarshal")
		} else {
			vi.VulnOverview = pre
		}
	}
}

func (vi *CacheInfo) Check() error {
	if vi.DataType == CacheTypeImagePrepare && vi.ImagePrepareData == nil {
		return fmt.Errorf("not get ImagePrepareData")
	}
	if vi.DataType == CacheTypVulnOverview && vi.VulnOverview == nil {
		return fmt.Errorf("not get VulnOverview")
	}

	return nil
}

func (vi *CacheInfo) ToUpdater() map[string]interface{} {
	updater := map[string]interface{}{
		"data":       vi.Data,
		"updated_at": time.Now().UTC().UnixMilli(),
	}

	return updater
}

func (vi *CacheInfo) TableName() string {
	return "ivan_scan_image_cache"
}

const (
	CacheTypeImagePrepare = "imagePrepare"
	CacheTypVulnOverview  = "vulnOverview"
)
