package imagesec

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/pkg/i18"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type ScanImageConfig struct {
	ID              int64            `gorm:"column:id" json:"id"`
	ConfigType      string           `gorm:"column:config_type" json:"configType"` // 配置类型
	ConfigData      string           `gorm:"column:config_data" json:"configData"`
	NodeImageConfig *NodeImageConfig `gorm:"-" json:"nodeImageConfig"`
	CreatedAt       int64            `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt       int64            `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
}

func (vi *ScanImageConfig) Check() *i18.ErrI18 {
	if vi.ConfigType == "" {
		return i18.CreateI18BadReqErr("没有获取到配置类型", "not get configType")
	}
	if vi.NodeImageConfig != nil {
		if err := vi.NodeImageConfig.Check(); err != nil {
			return err
		}
	}
	return nil
}

func (vi *ScanImageConfig) ToUpdater() map[string]interface{} {
	vi.Serialize()
	up := map[string]interface{}{
		"config_data": vi.ConfigData,
		"updated_at":  time.Now().UnixMilli(),
	}
	return up
}

func (vi *ScanImageConfig) TableName() string {
	return "ivan_scan_image_config"
}

func (vi *ScanImageConfig) Deserialize() {

	if vi.ConfigType == ConfigTypeNodeScanImage {
		empty := &NodeImageConfig{}
		nodeImageConfig := &NodeImageConfig{}
		if err := json.Unmarshal([]byte(vi.ConfigData), nodeImageConfig); err != nil {
			logging.Get().Err(err).Msg("ScanImageConfig Deserialize")
			vi.NodeImageConfig = empty
		} else {
			vi.NodeImageConfig = nodeImageConfig
		}
		if len(vi.NodeImageConfig.ScanCycle.ClusterKey) == 0 {
			vi.NodeImageConfig.ScanCycle.ClusterKey = make([]string, 0)
		}

		if len(vi.NodeImageConfig.ScanCycle.Day) == 0 {
			vi.NodeImageConfig.ScanCycle.Day = make([]int64, 0)
		}

		if len(vi.NodeImageConfig.ScanCycle.Weekday) == 0 {
			vi.NodeImageConfig.ScanCycle.Weekday = make([]int64, 0)
		}
		vi.NodeImageConfig.ID = vi.ID
	}
}

func (vi *ScanImageConfig) Serialize() {

	if vi.ConfigType == ConfigTypeNodeScanImage {
		vi.NodeImageConfig.ScanCycle.Serialize()

		bys, err := json.Marshal(vi.NodeImageConfig)
		if err != nil {
			logging.Get().Err(err).Msg("ScanImageConfig Serialize")
		} else {
			vi.ConfigData = string(bys)
		}
	}
}

type NodeImageConfig struct {
	ID             int64     `json:"id"`
	VulnFlush      bool      `json:"vulnFlush"`
	MalwareFlush   bool      `json:"malwareFlush"`
	SensitiveFlush bool      `json:"sensitiveFlush"`
	AutoScanAdded  bool      `json:"autoScanAdded"`
	DeepScan       bool      `json:"deepScan"`
	SyncInterval   int64     `json:"syncInterval"`  // 单位分钟
	ScanTimeout    int64     `json:"scanTimeout"`   // 单个镜像超时设置:单位分钟
	ClearInterval  int64     `json:"clearInterval"` // 单位：天
	ScanCycle      ScanCycle `json:"scanCycle"`
	Updater        string    `json:"updater"`
}

type ScanCycle struct {
	Enable         bool     `json:"enable"`         // 周期扫描开关
	ClusterKey     []string `json:"clusterKey"`     // 扫描集群的 clusterKey
	AllCluster     bool     `json:"allCluster"`     // 未选 cluster 时扫描全部
	ScanTime       string   `json:"scanTime"`       // 扫描时间:12:23:20的格式
	ScanTimeHour   int64    `json:"scanTimeHour"`   // 扫描时间
	ScanTimeMinute int64    `json:"scanTimeMinute"` // 扫描时间
	Day            []int64  `json:"day"`            // 一个月中那些特定的天需要扫描
	Weekday        []int64  `json:"weekday"`
	Mouth          []int64  `json:"mouth"`
	CycleType      string   `json:"cycleType"`
}

func (vi *ScanCycle) Serialize() {
	split := strings.Split(vi.ScanTime, ":")
	if len(split) < 3 {
		return
	}
	h, err := strconv.Atoi(split[0])
	if err != nil {
		return
	}
	m, err := strconv.Atoi(split[1])
	if err != nil {
		return
	}

	vi.ScanTimeHour = int64(h)
	vi.ScanTimeMinute = int64(m)

	vi.Day = util.SortInt64Slice(util.DuplicateInt64Slice(vi.Day))
	vi.Weekday = util.SortInt64Slice(util.DuplicateInt64Slice(vi.Weekday))
	vi.Mouth = util.SortInt64Slice(util.DuplicateInt64Slice(vi.Mouth))
}

func (vi *ScanCycle) Check() *i18.ErrI18 {
	if err := checkTime(vi.ScanTime); err != nil {
		return i18.CreateI18BadReqErr("周期扫描时间不正确", "cycle scan time is incorrect")
	}

	split := strings.Split(vi.ScanTime, ":")
	if len(split) < 2 {
		return i18.CreateI18BadReqErr("周期扫描时间不正确", "cycle scan time is incorrect")
	}
	h, err := strconv.Atoi(split[0])
	if err != nil {
		return i18.CreateI18BadReqErr("周期扫描时间不正确", "cycle scan time is incorrect")
	}
	m, err := strconv.Atoi(split[1])
	if err != nil {
		return i18.CreateI18BadReqErr("周期扫描时间不正确", "cycle scan time is incorrect")
	}

	vi.ScanTimeHour = int64(h)
	vi.ScanTimeMinute = int64(m)

	if vi.ScanTimeHour > 24 || vi.ScanTimeHour < 0 {
		return i18.CreateI18BadReqErr("周期扫描时间不正确", "cycle scan time is incorrect")
	}

	if vi.ScanTimeMinute > 60 || vi.ScanTimeMinute < 0 {
		return i18.CreateI18BadReqErr("周期扫描时间不正确", "cycle scan time is incorrect")
	}
	for i := range vi.Day {
		if vi.Day[i] <= 0 || vi.Day[i] > 31 {
			return i18.CreateI18BadReqErr("周期扫描时间不正确", "cycle scan time is incorrect")
		}
	}

	for i := range vi.Weekday {
		if vi.Weekday[i] < 0 || vi.Weekday[i] > 6 {
			return i18.CreateI18BadReqErr("周期扫描时间不正确", "cycle scan time is incorrect")
		}
	}
	if !util.ExistInStringSlice([]string{CycleTypeWeekday, CycleTypeDay, CycleTypeMonth}, vi.CycleType) {
		return i18.CreateI18BadReqErr("周期扫描类型不正确", "cycle scan type is incorrect")
	}

	return nil
}

func (vi *NodeImageConfig) IsTimeToAddTask(checkInter time.Duration) bool {
	logging.Get().Debug().Msgf("AddTaskByStrategy config: %+v", vi)
	now := time.Now().UTC().Add(time.Hour * 8)
	add := false
	nowW := now.Weekday()
	nowDay := now.Day()

	if vi.ScanCycle.CycleType == CycleTypeWeekday {
		logging.Get().Info().Msgf("AddTaskByStrategy,now weekday:%d ,%+v", nowW, vi.ScanCycle.Weekday)
		for i := range vi.ScanCycle.Weekday {
			if vi.ScanCycle.Weekday[i] == int64(nowW) {
				add = true
				break
			}
		}
	}

	if vi.ScanCycle.CycleType == CycleTypeMonth {
		logging.Get().Info().Msgf("AddTaskByStrategy,now weekday:%d ,%+v", nowW, vi.ScanCycle.Weekday)
		for i := range vi.ScanCycle.Day {
			if vi.ScanCycle.Day[i] == int64(nowDay) {
				add = true
				break
			}
		}
	}
	if vi.ScanCycle.CycleType == CycleTypeDay {
		logging.Get().Info().Msgf("AddTaskByStrategy,every day")
		add = true
	}
	if add {
		year, month, day := now.Date()
		next := time.Date(year, month, day, int(vi.ScanCycle.ScanTimeHour), int(vi.ScanCycle.ScanTimeMinute), 0, 0, time.UTC)

		logging.Get().Info().Msgf("AddTaskByStrategy,next:%s,now:%s", next.String(), now.String())
		if now.Sub(next) <= checkInter && now.Sub(next) > 0 {
			logging.Get().Info().Bool("addTask", true).Msgf("AddTaskByStrategy it is time to add scan task")
			return true
		}
	}
	return false
}

func checkTime(ti string) error {
	split := strings.Split(ti, ":")
	if len(split) < 2 {
		return fmt.Errorf("scan time is not standard:%s", ti)
	}
	p1, err := strconv.ParseInt(split[0], 10, 64)
	if err != nil {
		return fmt.Errorf("scan time is not standard:%s", ti)
	}
	if p1 < 0 || p1 > 23 {
		return fmt.Errorf("scan time is not standard:%s", ti)
	}
	p2, err := strconv.ParseInt(split[1], 10, 64)
	if err != nil {
		return fmt.Errorf("scan time is not standard:%s", ti)
	}
	if p2 < 0 || p2 > 59 {
		return fmt.Errorf("scan time is not standard:%s", ti)
	}
	return nil
}

func (vi *NodeImageConfig) Check() *i18.ErrI18 {
	if vi.ScanCycle.CycleType == "" {
		return i18.CreateI18BadReqErr("未获取周期扫描类型", "not get cycle type")
	}
	if vi.SyncInterval < 10 {
		return i18.CreateI18BadReqErr("镜像同步间隔不得低10分钟", "sync interval cannot less than 10 minutes")
	}
	if vi.ScanTimeout < 1 {
		return i18.CreateI18BadReqErr("镜像扫描超时时间不得低1分钟", "image scan timeout cannot setting less than 1 minute")
	}
	if vi.ClearInterval < 1 {
		return i18.CreateI18BadReqErr("镜像清理时间间隔不得低1天", "image cleanup interval cannot less than 1 day")
	}
	if err := vi.ScanCycle.Check(); err != nil {
		return err
	}
	return nil
}

// 敏感文件规则
type SensitiveRule struct {
	ID          int64  `gorm:"primaryKey" json:"id"`
	Description string `gorm:"column:description" json:"description"`
	Value       string `gorm:"column:value" json:"value"`        // 唯一
	RuleType    string `gorm:"column:rule_type" json:"ruleType"` // filename fileContent
	IsDefault   bool   `gorm:"column:is_default" json:"isDefault"`
	Enable      bool   `gorm:"enable" json:"enable"`
	Updater     string `gorm:"column:updater" json:"updater"`
	Creator     string `gorm:"column:creator" json:"creator"`
	CreatedAt   int64  `gorm:"autoCreateTime:milli;column:created_at" json:"createdAt"` // milliseconds
	UpdatedAt   int64  `gorm:"autoUpdateTime:milli;column:updated_at" json:"updatedAt"` // milliseconds
}

func (vi *SensitiveRule) ToUpdater() map[string]interface{} {
	return map[string]interface{}{
		"description": vi.Description,
		"value":       vi.Value,
		"enable":      vi.Enable,
		"updater":     vi.Updater,
	}
}

func (vi *SensitiveRule) TableName() string {
	return "ivan_scan_sensitive_rule"
}

func (vi *SensitiveRule) Check() *i18.ErrI18 {
	vi.Value = strings.TrimSpace(vi.Value)
	if vi == nil {
		return i18.CreateI18BadReqErr("程序出错", "not get model")
	}
	if vi.Value == "" {
		return i18.CreateI18BadReqErr("未获取到敏感文件名", "not get sensitive rule value")
	}
	if vi.RuleType == "" {
		vi.RuleType = SensitiveRuleTypeFilename
	}
	if vi.Creator != "" && vi.Updater == "" {
		vi.Updater = vi.Creator
	}
	if vi.Creator == "" && vi.Updater == "" {
		return i18.CreateI18BadReqErr("未获取到创建人或更新人", "not get creator or updater")
	}

	if _, err := regexp.Compile(vi.Value); err != nil {
		return i18.CreateI18BadReqErr("敏感文件名不是正确的正则表达式", "sensitive file rules are not correct regular expressions")
	}

	return nil
}
