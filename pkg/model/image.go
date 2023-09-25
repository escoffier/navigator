package model

import (
	"fmt"
	"strings"
	"time"

	json "github.com/json-iterator/go"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	scannermodel "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ImageInfo struct {
	ID           int64  `json:"id"`
	Digest       string `json:"digest"`
	FullRepoName string `json:"full_repo_name"`
	Library      string `json:"library"`
	Tags         string `json:"tags"`
}

type QuestionInfo struct {
	QID          int    `gorm:"primary_key;AUTO_INCREMENT" json:"-" `
	ID           int    `gorm:"column:id;index" json:"id"`
	Digest       string `gorm:"column:digest;index" json:"digest,omitempty"`
	Info         string `gorm:"-"`
	LinkObjectId string `gorm:"column:link_object_id" json:"link_object_id,omitempty"` // mongo scantask表的ID
	Time         string `gorm:"column:time" json:"timem,omitempty"`
}

func (q QuestionInfo) TableName() string {
	return "tensor_question"
}

type VirusFileInfo struct {
	Filename  string `json:"filename"`
	Filepath  string `json:"filepath"`
	Virusname string `json:"virusname"`
}

type WebshellFileInfo struct {
	Filename string   `json:"filename"`
	Filepath string   `json:"filepath"`
	Score    int64    `json:"score"`
	Codes    []string `json:"codes"`
}

type Artifacts struct {
	Af2 []Artifacts2
	Af1 []Artifacts1
}

type Artifacts2 struct {
	FullRepoName  string `json:"full_repo_name"`
	AdditionLinks struct {
		BuildHistory struct {
			Absolute bool   `json:"absolute"`
			Href     string `json:"href"`
		} `json:"build_history"`
		Vulnerabilities struct {
			Absolute bool   `json:"absolute"`
			Href     string `json:"href"`
		} `json:"vulnerabilities"`
	} `json:"addition_links"`
	Digest     string `json:"digest"`
	ExtraAttrs struct {
		Architecture string `json:"architecture"`
		Author       string `json:"author"`
		Config       struct {
			Entrypoint []string `json:"Entrypoint"`
			Env        []string `json:"Env"`
			Labels     struct {
				OrgLabelSchemaBuildDate        string `json:"org.label-schema.build-date"`
				OrgLabelSchemaLicense          string `json:"org.label-schema.license"`
				OrgLabelSchemaName             string `json:"org.label-schema.name"`
				OrgLabelSchemaSchemaVersion    string `json:"org.label-schema.schema-version"`
				OrgLabelSchemaVendor           string `json:"org.label-schema.vendor"`
				OrgOpencontainersImageCreated  string `json:"org.opencontainers.image.created"`
				OrgOpencontainersImageLicenses string `json:"org.opencontainers.image.licenses"`
				OrgOpencontainersImageTitle    string `json:"org.opencontainers.image.title"`
				OrgOpencontainersImageVendor   string `json:"org.opencontainers.image.vendor"`
			} `json:"Labels"`
			WorkingDir string `json:"WorkingDir"`
		} `json:"config"`
		Created time.Time `json:"created"`
		Os      string    `json:"os"`
	} `json:"extra_attrs"`
	Icon              string      `json:"icon"`
	ID                int         `json:"id"`
	Labels            interface{} `json:"labels"`
	ManifestMediaType string      `json:"manifest_media_type"`
	MediaType         string      `json:"media_type"`
	ProjectID         int         `json:"project_id"`
	PullTime          time.Time   `json:"pull_time"`
	PushTime          time.Time   `json:"push_time"`
	References        interface{} `json:"references"`
	RepositoryID      int         `json:"repository_id"`
	Size              int         `json:"size"`
	Tags              []struct {
		ArtifactID   int    `json:"artifact_id"`
		ID           int    `json:"id"`
		Immutable    bool   `json:"immutable"`
		Name         string `json:"name"`
		PullTime     string `json:"pull_time"`
		PushTime     string `json:"push_time"`
		RepositoryID int    `json:"repository_id"`
		Signed       bool   `json:"signed"`
	} `json:"tags"`
	Type string `json:"type"`
}

type Artifacts1 struct {
	FullRepoName  string `json:"full_repo_name"`
	Digest        string `json:"digest"`
	Name          string `json:"name"`
	Size          int    `json:"size"`
	Architecture  string `json:"architecture"`
	Os            string `json:"os"`
	OsVersion     string `json:"os.version"`
	DockerVersion string `json:"docker_version"`
	Author        string `json:"author"`
	Created       string `json:"created"`
	Config        struct {
		Labels interface{} `json:"labels"`
	} `json:"config"`
	Immutable bool          `json:"immutable"`
	Signature interface{}   `json:"signature"`
	Labels    []interface{} `json:"labels"`
	PushTime  time.Time     `json:"push_time"`
	PullTime  time.Time     `json:"pull_time"`
}

// ImageList 镜像信息表
type ImageList struct {
	ID                int64                   `gorm:"primary_key;AUTO_INCREMENT" json:"id" `
	CreatedAt         time.Time               `json:"created_at"`
	UpdatedAt         time.Time               `json:"updated_at"`
	FullRepoName      string                  `gorm:"type:varchar(255)"  json:"full_repo_name"`
	Tags              string                  `gorm:"type:varchar(255)" json:"tags"`
	Digest            string                  `gorm:"type:varchar(255);index:idx_image_digest" json:"digest"`
	OS                string                  `gorm:"type:varchar(255);column:os" json:"os"`
	Size              int                     `gorm:"column:size" json:"size"`
	Library           string                  `gorm:"type:varchar(255);column:library" json:"library"`
	ImageUUID         uint32                  `gorm:"column:image_uuid" json:"imageUUID"`
	Questions         []QuestionInfo          `gorm:"-" json:"questions"`
	ImageScanVuln     ImageScanSummaryResult  `gorm:"-" json:"image_scan_vuln"`
	ScanStatus        int                     `gorm:"-" json:"scan_status"`
	ImageScanVirus    []VirusFileInfo         `gorm:"-" json:"image_scan_virus"`
	ImageScanWebshell []scannermodel.Webshell `gorm:"-" json:"image_scan_webshell"`
	ImageScanEnv      []SummaryEnv            `gorm:"-"  json:"image_scan_env"`
	OnLineCount       int                     `gorm:"column:on_line_count;default:0" json:"-"`
	Status            int                     `gorm:"column:status;default:0" json:"status"`           //  status: -1 not ready images 0 normal status
	RegistryID        int64                   `gorm:"column:registry_id;default:0" json:"registry_id"` // 来源registry，id为registry表的id
	FirstPushTime     time.Time
	LastPushTime      time.Time   `gorm:"not null"` // 上次push时间
	LastPullTime      time.Time   // 上次pull时间
	ManifestV1        *ManifestV1 `gorm:"-" json:"manifest_v1" `
	ManifestV2        *ManifestV2 `gorm:"-" json:"manifest_v2"`
	ConfigFile        *ConfigFile `gorm:"-" json:"config"`

	ManifestV1JSON []byte `gorm:"type:Blob"` // manifest内容
	ManifestV2JSON []byte `gorm:"type:Blob"`
	ConfigJSON     []byte `gorm:"type:MediumBlob"`                                             // config内容,包括layer diffid
	FromType       int64  `gorm:"column:from_type;default:0" json:"from_type"`                 // 镜像来源
	Layers         string `gorm:"type:text;index:idx_image_layers,length:200" json:"layers"`   // 把layer拼成字符串，为了找出基础镜像,用|分隔
	NodeIP         string `gorm:"type:varchar(255);column:node_ip" json:"node_ip"`             // 结点的Ip
	NodeHostname   string `gorm:"type:varchar(255);column:node_hostname" json:"node_hostname"` // 结点的HostName

	ImageType int64 `gorm:"column:image_type;default:0" json:"image_type"`

	ScanImage *ScanImage `gorm:"-" json:"scan_image"`
	Registry  *Registry  `gorm:"-" json:"registry"`

	Project        string `gorm:"type:varchar(255);project" json:"project"`     // 项目 用于报表统计
	RepoName       string `gorm:"type:varchar(255);repo_name" json:"repo_name"` // 仓库名 用于报表统计
	PrivilegedBoot int64  `gorm:"privileged_boot" json:"privileged_boot"`
	IsReinforce    int    `gorm:"is_reinforce" json:"is_reinforce"`

	CheckSum       uint64 `gorm:"column:check_sum" json:"check_sum,string"`       // 这一行数据的check值，且于判断这一行数据是否有变动，如果没有变动，就不再更新
	UniqueImage    uint64 `gorm:"column:unique_image" json:"unique_image,string"` // 由fullreponame+tags+registryId+fromType生成uuid，唯一确定一定镜像，优化查询
	Flag           uint64 `gorm:"column:flag" json:"flag,string"`
	LastFullSyncAt int64  `gorm:"column:last_full_sync_at" json:"last_full_sync_at"`

	Online               bool      `gorm:"-" json:"online"`
	LastScanAt           time.Time `gorm:"-" json:"last_scan_at"`
	Trusted              bool      `gorm:"-"  json:"trusted"`
	VulnFixSuggestion    []string  `gorm:"-" json:"vulnFixSuggestion"`
	SentiveFixSuggestion []string  `gorm:"-" json:"sentiveFixSuggestion"`
}

func (im *ImageList) GenImageUUID() uint32 {
	imageName := im.GetImageName()
	imageName = strings.ReplaceAll(imageName, "https://", "")
	imageName = strings.ReplaceAll(imageName, "http://", "")
	return util.GenerateUUID(imageName)
}

func (im *ImageList) GetBootUser() string {
	user := ""
	if im.ConfigFile != nil {
		user = im.ConfigFile.Config.User
		if user == "" {
			user = "root"
		}
	}
	return user
}

func (im *ImageList) GetImageName() string {
	return fmt.Sprintf("%s/%s:%s", im.Library, im.FullRepoName, im.Tags)
}

func (im *ImageList) FromTypeToString() string {
	switch im.FromType {
	case UserRegistry:
		return UserRegistryString
	case NodeBuffRegistry:
		return NodeBuffRegistryString
	case CICDImageRegistry:
		return CICDImageRegistryString
	}
	return ""
}

func (im *ImageList) SetScanStatusFlag(status uint64) {
	// if status < imagesec.FlagImageScanUnknown || status > imagesec.FlagImageNotScan {
	// 	return
	// }
	// scanStatusFlag := imagesec.GetScanStatusFlag()
	//
	// flag := im.Flag
	// for i := range scanStatusFlag {
	// 	flag = util.SetBit0(flag, scanStatusFlag[i])
	// }
	//
	// // 然后设置成1
	// flag = util.SetBit1(flag, status)
	// im.Flag = flag
}

func (im *ImageList) IsItNotScanned() bool {
	// scanStatusFlag := imagesec.GetScanStatusFlag()
	// flag := im.Flag
	//
	// for i := range scanStatusFlag {
	// 	if flag&(1<<scanStatusFlag[i]) == 1 {
	// 		return true
	// 	}
	// }
	return false
}

func (im *ImageList) SetFlagBaseImage() {
	// flag := im.Flag
	// flag = util.SetBit1(flag, imagesec.FlagBaseImage)
	// im.Flag = flag
}

func (im *ImageList) SetFlagAppImage() {
	// flag := im.Flag
	// flag = util.SetBit0(flag, imagesec.FlagBaseImage)
	// im.Flag = flag
}

func (im *ImageList) Serialize() {
	if im.ManifestV1 != nil {
		bys, err := json.Marshal(im.ManifestV1)
		if err != nil {
			logging.GetLogger().Error().Err(err).Int64("ImageId", im.ID).Msg("ImageList,Serialize")
		} else {
			im.ManifestV1JSON = bys
		}
	}
	if im.ManifestV2 != nil {
		bys, err := json.Marshal(im.ManifestV2)
		if err != nil {
			logging.GetLogger().Error().Err(err).Int64("ImageId", im.ID).Msg("ImageList,Serialize")
		} else {
			im.ManifestV2JSON = bys
		}
	}
	if im.ConfigFile != nil {
		bys, err := json.Marshal(im.ConfigFile)
		if err != nil {
			logging.GetLogger().Error().Err(err).Int64("ImageId", im.ID).Msg("ImageList,Serialize")
		} else {
			im.ConfigJSON = bys
		}
	}
}

func (im *ImageList) Deserialize() {
	if len(im.ManifestV1JSON) > 0 {
		ll := new(ManifestV1)
		err := json.Unmarshal(im.ManifestV1JSON, ll)
		if err != nil {
			logging.GetLogger().Error().Err(err).Int64("ImageId", im.ID).Msg("ImageList,Deserialize")
		} else {
			im.ManifestV1 = ll
		}
	}

	if len(im.ManifestV2JSON) > 0 {
		ll := new(ManifestV2)
		err := json.Unmarshal(im.ManifestV2JSON, ll)
		if err != nil {
			logging.GetLogger().Error().Err(err).Int64("ImageId", im.ID).Msg("ImageList,Deserialize")
		} else {
			im.ManifestV2 = ll
		}
	}

	if len(im.ConfigJSON) > 0 {
		ll := new(ConfigFile)
		err := json.Unmarshal(im.ConfigJSON, ll)
		if err != nil {
			logging.GetLogger().Error().Err(err).Int64("ImageId", im.ID).Msg("ImageList,Deserialize")
		} else {
			im.ConfigFile = ll
		}
	}
}

func (ImageList) TableName() string {
	return "ivan_scanner_image_list"
}

func (im *ImageList) GenUniqueImage() uint64 {
	uid := util.GenerateUUID64(fmt.Sprintf(consts.UniqueImageFamat, im.FullRepoName, im.Tags, im.FromType, im.RegistryID))
	return uid
}

func (im *ImageList) GenImageCheckSum() uint64 {
	if im.CheckSum > 0 {
		return im.CheckSum
	}
	im.Serialize()
	im.Deserialize()
	createdAt, updatedAt, preCheck, last := im.CreatedAt, im.UpdatedAt, im.CheckSum, im.LastFullSyncAt
	im.CreatedAt = time.Time{}
	im.UpdatedAt = time.Time{}
	im.CheckSum = 0
	im.OnLineCount = 0
	im.Status = 0
	im.LastFullSyncAt = 0

	bys, err := json.Marshal(im)
	im.CreatedAt, im.UpdatedAt, im.CheckSum, im.LastFullSyncAt = createdAt, updatedAt, preCheck, last
	if err != nil {
		return 0
	}
	return util.GenerateUUID64(string(bys))
}

func (im *ImageList) GetLayerString() string {
	if im.Layers != "" {
		return im.Layers
	}

	lays := make([]string, 0)
	im.Deserialize()

	// 先看v2
	if im.ManifestV2 != nil {
		for j := range im.ManifestV2.Layers {
			lays = append(lays, im.ManifestV2.Layers[j].Digest)
		}
	}

	// 再看v1
	if len(lays) == 0 && im.ManifestV1 != nil {
		for j := range im.ManifestV1.HistoryV1 {
			lays = append(lays, "sha256:"+im.ManifestV1.HistoryV1[j].LayerDigest)
		}
	}
	// 转成uuid的方式，缩短索引长度
	for i := range lays {
		lays[i] = fmt.Sprintf("%d", util.GenerateUUID(lays[i]))
	}

	return strings.Join(lays, "|")
}

func (im *ImageList) GenImageFlag() {
	// flag := im.Flag
	// boot := false
	//
	// if im.ConfigFile != nil {
	// 	if im.ConfigFile.Config.User == "" || strings.Contains(im.ConfigFile.Config.User, "root") {
	// 		flag = util.SetBit1(flag, imagesec.FlagExceptionBoot)
	// 		boot = true
	// 	}
	// }
	// if !boot {
	// 	flag = util.SetBit0(flag, imagesec.FlagExceptionBoot)
	// }
	// im.Flag = flag
}

// 兼容老代码，等稳定运行一个版本后，再删除
type Registry struct {
	ID              int64  `gorm:"primaryKey" json:"id"`
	Name            string `gorm:"type:varchar(255);uniqueIndex:uniq_idx_registry_name;priority:1" json:"name"` // 仓库名字,仓库名是仓库的唯一标识,一个仓库名称  对应一个用户
	RegType         string `gorm:"type:varchar(255);column:reg_type" json:"reg_type"`                           // 仓库类型
	Url             string `gorm:"type:varchar(255);column:url" json:"url"`                                     // 如:docker.io/v2, quay.io/v2
	Username        string `gorm:"type:varchar(255);column:username" json:"username"`                           // user for login registry
	Password        []byte `gorm:"type:blob" json:"-"`                                                          // DES加密
	PasswordString  string `gorm:"-" json:"password"`
	Token           string `gorm:"-" json:"token"`
	Description     string `gorm:"type:varchar(255);column:description"  json:"description"`
	AuthStr         string `gorm:"-" json:"auth_str"`                         // 用户名和密码加密后的数据，不存入数据库中
	SyncInterval    int64  `gorm:"column:sync_interval" json:"sync_interval"` // 单位：分钟
	LastSyncAt      int64  `gorm:"column:last_sync_at" json:"last_sync_at"`   // 最后一次同步时间(单位：秒)
	AccessKey       string `gorm:"access_key" json:"access_key"`              // 阿里云仓库的AccessKey
	AccessSecret    string `gorm:"access_secret" json:"access_secret"`        // 阿里云仓库的AccessSecret
	InstanceID      string `gorm:"instance_id" json:"instance_id"`            // 阿里云仓库企业版实例ID
	RegionID        string `gorm:"region_id" json:"region_id"`                // 阿里云仓库企业版地域ID
	ScannerInstance string `gorm:"scanner_instance" json:"scanner_instance"`  // 当前仓库所用扫描器
	Status          string `gorm:"column:status" json:"status"`               // 健康状况
	HealthMsg       string `gorm:"column:health_msg" json:"health_msg"`       // 不健康时的错误信息
	HeatBeat        int64  `gorm:"column:heat_beat" json:"heat_beat"`         // 上一次检查时间

	CreatedAt time.Time `gorm:"column:created_at" json:"created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at" json:"updated_at"`
	DeletedAt int64     `gorm:"column:deleted_at; default:0;uniqueIndex:uniq_idx_registry_name;priority:2" json:"deleted_at"`
}
