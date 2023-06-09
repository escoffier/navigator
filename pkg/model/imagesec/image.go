package imagesec

import (
	"encoding/json"
	"fmt"
	"strings"

	"scm.tensorsecurity.cn/tensorsecurity-rd/fanal/types"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecTypes "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

// 镜像元信息
type Image struct {
	ID            int64                 `gorm:"primary_key;AUTO_INCREMENT" json:"id" `
	UniqueID      uint64                `gorm:"column:unique_id" json:"uniqueID,string"`     // 生成的ID，写入关联数据时就不用事务
	ImageFromType string                `gorm:"column:image_from_type" json:"imageFromType"` // CI,NODE,LIB 这三类
	ImageID       string                `gorm:"column:image_id" json:"imageID"`              // 对于节点镜像，部分镜像是没有digest这个信息的
	Host          string                `gorm:"column:host" json:"host"`
	Repo          string                `gorm:"column:repo" json:"repo"`
	Tag           string                `gorm:"column:tag" json:"tag"`
	ImageName     string                `gorm:"column:image_name" json:"imageName"` // 主要用于搜索
	Digest        string                `gorm:"column:digest" json:"digest"`
	OS            types.OS              `gorm:"-" json:"os"` // 为啥不用 ImageOS :为了兼容老数据,返回数据为啥要定义新结构体:因为 trivy 的Eosl 可能不序列化
	OSJson        string                `gorm:"column:os" json:"-"`
	Size          int64                 `gorm:"column:size" json:"size"` // 单位：byte
	LayerJSON     string                `gorm:"column:layer" json:"-"`
	Layer         []imagesecTypes.Layer `gorm:"-" json:"layer"`
	BuildAt       int64                 `gorm:"column:build_at" json:"buildAt"` // build时间
	User          string                `gorm:"column:user" json:"user"`        // 启动用户
	Flag          uint64                `gorm:"column:flag" json:"flag,string"` // 最近一次镜像元信息
	ImageUUID     uint32                `gorm:"column:image_uuid" json:"imageUUID"`
	RegID         int64                 `gorm:"column:reg_id" json:"regID"`
	NodeID        uint64                `gorm:"column:node_id" json:"nodeID,string"`
	Project       string                `gorm:"column:project" json:"project"`                           // 仓库层级
	Heartbeat     int64                 `gorm:"column:heartbeat" json:"heartbeat"`                       // 上一次上报的心跳 milliseconds
	CreatedAt     int64                 `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt     int64                 `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
}

const (
	DockerHost = "index.docker.io"
)

func (vi *Image) BootRoot() bool {
	if vi == nil {
		return false
	}
	return vi.User == "" || vi.User == BootRootUser
}

func (vi *Image) GetImageName() string {
	if vi == nil {
		return ""
	}

	imageName := vi.Repo + ":" + vi.Tag
	if vi.Host != "" && !strings.Contains(vi.Host, DockerHost) {
		imageName = vi.Host + "/" + imageName
	}
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
}

func (vi *Image) Serialize() {

	vi.Flag = vi.GenDefaultFlag()

	if byt, err := json.Marshal(vi.Layer); err == nil {
		vi.LayerJSON = string(byt)
	}

	if bys, err := json.Marshal(vi.OS); err == nil {
		vi.OSJson = string(bys)
	}
	if vi.User == BootRootUser || vi.User == "" {
		vi.Flag = util.SetBit1(vi.Flag, model.FlagPrivilegedBoot)
	}
	if strings.Contains(vi.Host, DockerHost) {
		vi.Host = ""
		vi.Repo = strings.Replace(vi.Repo, "library/", "", 1)
	}
	vi.ImageName = vi.GetImageName()

	vi.UniqueID = vi.GenUniqueID()
	vi.ImageUUID = vi.GenUUID()
}

func (vi *Image) DeepCopy() *Image {
	bts, _ := json.Marshal(vi)
	after := &Image{}

	_ = json.Unmarshal(bts, &after)
	return after
}

func (vi *Image) GenDefaultFlag() uint64 {
	var flag uint64
	flag = util.SetBit1(flag, model.FlagImageSafeUnknown)
	flag = util.SetBit1(flag, model.FlagImageUnTrusted)
	flag = util.SetBit1(flag, model.FlagImageNotOnline)
	flag = util.SetBit1(flag, model.FlagNodeImageNotInLib)
	flag = util.SetBit1(flag, model.FlagAppImage)

	if vi.User == BootRootUser || vi.User == "" {
		flag = util.SetBit1(flag, model.FlagPrivilegedBoot)
	}
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
	switch vi.ImageFromType {
	case ImageFromCI:
		return 0 // ci
	case ImageFromRegistry:
		return util.GenerateUUID64(fmt.Sprintf(UniqueLibImageFormat, vi.RegID, vi.ImageName, vi.Digest, vi.ImageFromType))
	case ImageFromNode:
		return util.GenerateUUID64(fmt.Sprintf(UniqueNodeImageFormat, vi.NodeID, vi.ImageName, vi.Digest, vi.ImageID, vi.ImageFromType))
	}
	return 0
}

func (vi *Image) GenUUID() uint32 {
	imageName := vi.GetImageName()
	imageName = strings.ReplaceAll(imageName, "https://", "")
	imageName = strings.ReplaceAll(imageName, "http://", "")
	return util.GenerateUUID(imageName)
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
type SecurityOverView struct {
	Total SecurityIssueStatic `json:"total"`
	Risk  SecurityIssueStatic `json:"risk"`
}

type SecurityIssueStatic struct {
	Vuln           int64 `json:"vuln"`
	Malware        int64 `json:"malware"`
	Sensitive      int64 `json:"sensitive"`
	Webshell       int64 `json:"webshell"`
	Env            int64 `json:"env"`
	Pkg            int64 `json:"pkg"`
	License        int64 `json:"license"`
	PrivilegedBoot int64 `json:"privilegedBoot"`
}
