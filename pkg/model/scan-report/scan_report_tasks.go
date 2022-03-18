package scan_report

import (
	"database/sql/driver"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	json "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	softdelete "gorm.io/plugin/soft_delete"
)

// TensorScanReportType 扫描报告的类型
type TensorScanReportType uint8

const (
	TensorScanReportTypeWeek      TensorScanReportType = iota + 1 // 周报
	TensorScanReportTypeMonth                                     // 月报
	TensorScanReportTypeCustomize                                 // 自定义
)

func (t TensorScanReportType) Value() (driver.Value, error) { return int64(t), nil }

func (t TensorScanReportType) String() string {
	switch t {
	case TensorScanReportTypeWeek:
		return "week"
	case TensorScanReportTypeMonth:
		return "month"
	case TensorScanReportTypeCustomize:
		return "customize"
	default:
		return ""
	}
}

// TensorScanReportContentType 报告内容
type TensorScanReportContentType uint8

const (
	TensorScanReportContentTypeRisk          TensorScanReportContentType = 1 << iota // 风险
	TensorScanReportContentTypeVulnerability                                         // 漏洞
	TensorScanReportContentTypeVirus                                                 // 病毒
	TensorScanReportContentTypeFix                                                   // 修复建议
)

func (t TensorScanReportContentType) Value() (driver.Value, error) { return int64(t), nil }

// TensorScanReportImageType 报告类型
type TensorScanReportImageType uint8

const (
	TensorScanReportImageTypeRegistry TensorScanReportImageType = 1 << iota // 仓库镜像
	TensorScanReportImageTypeNode                                           // 节点镜像
)

func (t TensorScanReportImageType) Value() (driver.Value, error) { return int64(t), nil }

// TensorScanReportRegistryImageType 仓库镜像类型
type TensorScanReportRegistryImageType uint8

const (
	TensorScanReportRegistryImageTypeProject            TensorScanReportRegistryImageType = iota + 1 // 项目
	TensorScanReportRegistryImageTypeRegistry                                                        // 仓库
	TensorScanReportRegistryImageTypeProjectAndRegistry                                              // 项目仓库
)

func (t TensorScanReportRegistryImageType) Value() (driver.Value, error) { return int64(t), nil }

// TensorScanReportTasks 扫描报告
type TensorScanReportTasks struct {
	ID     uint                 `gorm:"primarykey" json:"id"`
	Name   string               `gorm:"type:varchar(255);column:name;uniqueIndex:report_name_unique_index;property:1;comment:报告名称,长度限制,100个字符" json:"name"`
	Type   TensorScanReportType `gorm:"column:type;comment:报告类型：1:周报，2:月报，3:自定义" json:"type"`
	Emails []string             `gorm:"-" json:"emails"` // 接受邮箱

	ContentTypes    []int64                     `gorm:"-" json:"content_types"` // 报告内容, 镜像漏洞列表: 1, 风险信息总览: 2, 病毒列表: 3, 镜像修复建议: 4
	ContentTypeEnum TensorScanReportContentType `gorm:"column:content_type;comment:报告类型:风险镜像列表:0b1,漏洞列表:0b10,病毒列表:0b100,修复建议:0b1000,多个内容求或运算" json:"-"`

	ImageTypes    []int64                   `gorm:"-" json:"image_types"` // 报告对象, 仓库镜像: 1, 节点镜像: 2
	ImageTypeEnum TensorScanReportImageType `gorm:"column:image_type;comment:报告对象,仓库镜像:0b1, 节点镜像:0b10,多个求或运算" json:"-"`
	Comment       string                    `gorm:"type:varchar(255);column:comment;comment:报告描述，500字符限制" json:"comment"`

	CreatedAt time.Time            `json:"created_at"` // 创建时间
	UpdatedAt time.Time            `json:"-"`
	DeletedAt softdelete.DeletedAt `gorm:"uniqueIndex:report_name_unique_index;property:2;default:0" json:"-"`

	CycleDay       uint8 `gorm:"column:cycle_day;comment:间隔时间，可以表示周几或者每个月的第几号" json:"cycle_day"`
	StartTimeStamp int64 `gorm:"column:start_timestamp;comment:自定义的开始时间" json:"start_timestamp"`
	EndTimeStamp   int64 `gorm:"column:end_timestamp;comment:结束时间" json:"end_timestamp"`
	LastTimeStamp  int64 `gorm:"column:last_timestamp;comment:最后一次生成时间" json:"last_timestamp"`

	RegistryImageType TensorScanReportRegistryImageType `gorm:"column:registry_image_type;comment:仓库镜像类型 1:项目 2:仓库 3:项目仓库" json:"registry_image_type"`

	RegistryImageObjects []string `gorm:"-" json:"registry_image_objects,omitempty"` // 仓库镜像类型时的项目或者仓库或者项目仓库列表
	NodeImageObjects     []string `gorm:"-" json:"node_image_objects,omitempty"`     // 节点镜像类型时的节点镜像列表

	RegistryImageObjectsJson datatypes.JSON `gorm:"type:blob;column:registry_image_objects" json:"-"` // 镜像仓库
	NodeImageObjectsJson     datatypes.JSON `gorm:"type:blob;column:node_image_objects" json:"-"`     // 节点仓库
	EmailsJson               datatypes.JSON `gorm:"type:blob;column:emails" json:"-"`                 // 接受邮箱

	SubTaskType SubTaskType `gorm:"-" json:"-"` // 子任务类型
}

func (TensorScanReportTasks) TableName() string { return "ivan_scanner_report_tasks" }

func (t *TensorScanReportTasks) AfterFind(_ *gorm.DB) error {
	if t.ImageTypeEnum&TensorScanReportImageTypeRegistry == TensorScanReportImageTypeRegistry {
		if err := json.Unmarshal(t.RegistryImageObjectsJson, &t.RegistryImageObjects); err != nil {
			return errors.Wrap(err, "反序列化仓库镜像对象失败")
		}
		t.ImageTypes = append(t.ImageTypes, 1)
	}

	if t.ImageTypeEnum&TensorScanReportImageTypeNode == TensorScanReportImageTypeNode {
		if err := json.Unmarshal(t.NodeImageObjectsJson, &t.NodeImageObjects); err != nil {
			return errors.Wrap(err, "反序列化节点镜像对象失败")
		}
		t.ImageTypes = append(t.ImageTypes, 2)
	}

	// 获取报告内容
	for i := 0; i < 4; i++ {
		if x, _t := 1<<i, int(t.ContentTypeEnum); x&_t == x {
			t.ContentTypes = append(t.ContentTypes, int64(i+1))
		}
	}

	if err := json.Unmarshal(t.EmailsJson, &t.Emails); err != nil {
		return errors.Wrap(err, "反序列化邮箱失败")
	}

	return nil
}

func (t *TensorScanReportTasks) BeforeCreate(_ *gorm.DB) error {
	return t.createAndUpdateHook()
}

func (t *TensorScanReportTasks) BeforeUpdate(_ *gorm.DB) error {
	return t.createAndUpdateHook()
}

func (t *TensorScanReportTasks) createAndUpdateHook() error {
	var err error
	t.EmailsJson, err = json.Marshal(t.Emails)
	if err != nil {
		return errors.Wrap(err, "序列化邮箱失败")
	}

	for _, v := range t.ImageTypes {
		t.ImageTypeEnum |= 1 << (v - 1)
	}

	for _, v := range t.ContentTypes {
		t.ContentTypeEnum |= 1 << (v - 1)
	}

	if t.ImageTypeEnum&TensorScanReportImageTypeRegistry == TensorScanReportImageTypeRegistry {
		t.RegistryImageObjectsJson, err = json.Marshal(&t.RegistryImageObjects)
		if err != nil {
			return errors.Wrap(err, "序列化仓库镜像对象失败")
		}
	} else {
		t.RegistryImageObjectsJson = datatypes.JSON{}
	}

	if t.ImageTypeEnum&TensorScanReportImageTypeNode == TensorScanReportImageTypeNode {
		t.NodeImageObjectsJson, err = json.Marshal(&t.NodeImageObjects)
		if err != nil {
			return errors.Wrap(err, "反序列化节点镜像对象失败")
		}
	} else {
		t.NodeImageObjectsJson = datatypes.JSON{}
	}

	return nil
}

var emailRegex = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

// CheckValid 检查数据是否有效
func (t *TensorScanReportTasks) CheckValid() error {
	if t.Name == "" || utf8.RuneCountInString(t.Name) > 100 {
		return errors.New("报告名称不能为空或者长度超过100个字符")
	}

	switch t.Type {
	case TensorScanReportTypeWeek:
		if t.CycleDay < 1 || t.CycleDay > 7 {
			return errors.New("无效的周期")
		}
	case TensorScanReportTypeMonth:
		if t.CycleDay < 1 || t.CycleDay > 31 {
			return errors.New("无效的周期")
		}
	case TensorScanReportTypeCustomize:
		start, end := time.Unix(0, t.StartTimeStamp*int64(time.Millisecond)), time.Unix(0, t.EndTimeStamp*int64(time.Millisecond))
		if start.After(end) {
			return errors.New("结束时间早于开始时间")
		}
	default:
		return errors.New("无效的报告类型")
	}

	if len(t.Emails) == 0 {
		return errors.New("邮箱地址不能为空")
	}

	// check valid emails
	for i := range t.Emails {
		if !emailRegex.MatchString(t.Emails[i]) {
			return fmt.Errorf("无效的邮箱地址: %s", t.Emails[i])
		}
	}

	// check comments' length
	if utf8.RuneCountInString(t.Comment) > 500 {
		return errors.New("报告描述不能超过500个字符")
	}

	// 有效值 1-3
	if t.Type < TensorScanReportTypeWeek || t.Type > TensorScanReportTypeCustomize {
		return fmt.Errorf("无效的报告类型: %d", t.Type)
	}
	// 有效值 1-2
	for _, v := range t.ImageTypes {
		if v > 2 || v < 1 {
			return fmt.Errorf("无效的报告对象: %d", v)
		}

		switch v {
		case 1: // 镜像仓库。当报告对象包含 镜像仓库 时，则需要选择 镜像仓库 类型( 1:项目 2:仓库 3:项目仓库)
			if t.RegistryImageType < TensorScanReportRegistryImageTypeProject ||
				t.RegistryImageType > TensorScanReportRegistryImageTypeProjectAndRegistry {
				return errors.New("无效的仓库镜像类型")
			}
			// 检查 镜像仓库 类型 的值是否为空
			if len(t.RegistryImageObjects) == 0 {
				return errors.New("仓库镜像具体对象不能为空")
			}

			if t.RegistryImageType == TensorScanReportRegistryImageTypeProjectAndRegistry {
				for _, o := range t.RegistryImageObjects {
					if !strings.Contains(o, " ") {
						return errors.New("项目于仓库使用空格分割")
					}
				}
			}

		case 2: // 节点镜像。当报告对象包含 节点镜像 时，
			if len(t.NodeImageObjects) == 0 {
				return errors.New("节点镜像具体对象不能为空")
			}
		}
	}

	return nil
}

func (t *TensorScanReportTasks) GenSubtask() *TensorScanReportSubTasks {
	var startTimeStamp, endTimeStamp int64
	var now = time.Now().In(util.CSTSh)
	nowZero := now.Add(time.Duration(now.Hour()*3600+now.Minute()*60+now.Second()) * time.Second * -1) // 今天的零时

	// 设置第一个报告的
	switch t.Type {
	case TensorScanReportTypeCustomize:
		startTimeStamp, endTimeStamp = t.StartTimeStamp, t.EndTimeStamp
	case TensorScanReportTypeWeek:
		endTime := nowZero.AddDate(0, 0, int(t.CycleDay)-int(now.Weekday())).Add(time.Duration(t.EndTimeStamp) * time.Millisecond).In(util.CSTSh)
		if now.After(endTime) {
			endTime = endTime.AddDate(0, 0, 7).In(util.CSTSh)
		}
		endTimeStamp = endTime.Unix() * 1000
		startTimeStamp = endTime.AddDate(0, 0, -7).In(util.CSTSh).Unix() * 1000

	case TensorScanReportTypeMonth:
		endTime := nowZero.AddDate(0, 0, int(t.CycleDay)-now.Day()).Add(time.Duration(t.EndTimeStamp) * time.Millisecond).In(util.CSTSh)
		if now.After(endTime) {
			endTime = endTime.AddDate(0, 1, 0).In(util.CSTSh)
		}

		endTimeStamp = endTime.Unix() * 1000
		startTimeStamp = endTime.AddDate(0, -1, 0).In(util.CSTSh).Unix() * 1000
	}

	// 当任务类型不为自定义任务，并且子任务类型为一次性任务时，则结束时间为当前时间
	if t.Type != TensorScanReportTypeCustomize && t.SubTaskType == SubTaskTypeOnce {
		if endTime := time.Unix(0, endTimeStamp*int64(time.Millisecond)).In(util.CSTSh); now.After(endTime) {
			startTimeStamp = endTimeStamp
		}

		endTimeStamp = now.Unix() * 1000
	}

	subTask := &TensorScanReportSubTasks{
		Status:         SubTasksStatusWaiting,
		Type:           t.SubTaskType,
		StartTimeStamp: startTimeStamp,
		EndTimeStamp:   endTimeStamp,
	}

	return subTask
}
