package model

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

type ScanConfig struct {
	ID                        int64            `gorm:"id" json:"id"`
	VulnFlushTrigEnable       bool             `gorm:"vuln_flush_trig_enable" json:"vuln_flush_trig_enable"`               // 漏洞库更新时触发全量扫描
	MaliciousFlushTrigEnable  bool             `gorm:"malicious_flush_trig_enable" json:"malicious_flush_trig_enable"`     // 漏洞库更新时触发全量扫描
	LibraryImageAddTrigEnable bool             `gorm:"library_image_add_trig_enable" json:"library_image_add_trig_enable"` // 自动扫描仓库新增镜像
	NodeImageAddTrigEnable    bool             `gorm:"node_image_add_trig_enable" json:"node_image_add_trig_enable"`       // 自动扫描节点新增镜像
	LibraryImageConfig        *ScanConfigSinge `gorm:"-" json:"library_image_config"`                                      // 仓库镜像的策略
	LibraryImageJson          string           `gorm:"type:varchar(255);column:library_image_config" json:"-"`
	NodeImageConfig           *ScanConfigSinge `gorm:"-" json:"node_image_config"`                          // 节点镜像的策略
	NodeImageJson             string           `gorm:"type:varchar(255);column:node_image_config" json:"-"` // 节点镜像的策略

	CreatedAt time.Time `gorm:"created_at" json:"created_at"`
	UpdatedAt time.Time `gorm:"updated_at" json:"updated_at"`
	DeletedAt int       `gorm:"deleted_at" json:"deleted_at"`
}

func (ScanConfig) TableName() string {
	return "ivan_scanner_scan_config"
}

type ScanConfigSinge struct {
	ScanCycleEnable bool     `gorm:"scan_cycle_enable" json:"scan_cycle_enable"` // 周期扫描开关
	Libraries       []int64  `gorm:"libraries" json:"libraries"`                 // 扫描仓库,列表序列化后的值
	NodeHostnames   []string `gorm:"node_hostnames" json:"node_hostnames"`       // 扫描仓库,列表序列化后的值
	ScanAll         bool     `gorm:"scan_all" json:"scan_all"`
	ScanCycle       []int64  `gorm:"scan_cycle" json:"scan_cycle"`                 // 扫描周期表示星期几
	ScanTime        string   `gorm:"type:varchar(255);scan_time" json:"scan_time"` // 扫描时间
	StrategyID      int64    `gorm:"strategy_id" json:"strategy_id"`               // 扫描策略。这里对应的是策略ID
}

type ScanStrategy struct {
	ID                int64               `gorm:"column:id" json:"id"`
	Name              string              `gorm:"type:varchar(255);uniqueIndex:uniq_idx_scan_strategy_name,column:name" json:"name"` // 策略名唯一
	Describe          string              `gorm:"type:varchar(255);column:describe" json:"describe"`
	Operator          string              `gorm:"type:varchar(255);column:operator" json:"operator"`
	IsDefault         bool                `gorm:"is_default" json:"is_default"`
	SensitiveFileJson string              `gorm:"type:varchar(255);column:sensitive_file" json:"-"`
	SensitiveFile     []SensitiveFileScan `gorm:"-" json:"sensitive_file"`
	EnvsJson          string              `gorm:"type:varchar(255);column:envs" json:"-"`
	Envs              []string            `gorm:"-" json:"envs"`

	Software        []Software `gorm:"-" json:"software"`
	SoftwareJson    string     `gorm:"type:varchar(255);column:software" json:"-"`
	OpenLicenseJson string     `gorm:"type:varchar(255);column:open_license" json:"-"`
	OpenLicense     []string   `gorm:"-" json:"open_license"`

	EnvsEnable        bool `gorm:"envs_enable" json:"envs_enable"`
	SoftwareEnable    bool `gorm:"software_enable" json:"software_enable"`
	OpenLicenseEnable bool `gorm:"open_license_enable" json:"open_license_enable"`

	SensitiveEnable bool `gorm:"sensitive_enable" json:"sensitive_enable"`
	VulEnable       bool `gorm:"vul_enable" json:"vul_enable"`
	WebshellEnable  bool `gorm:"webshell_enable" json:"webshell_enable"`
	MaliciousEnable bool `gorm:"malicious_enable" json:"malicious_enable"`

	CreatedAt time.Time `gorm:"created_at" json:"created_at"`
	UpdatedAt time.Time `gorm:"updated_at" json:"updated_at"`
	DeletedAt int       `gorm:"deleted_at" json:"deleted_at"`
}

type SensitiveFileScan struct {
	Description string `json:"description"`
	SecretType  string `json:"secret_type"`
	Value       string `json:"value"`
}

func (s *ScanStrategy) TableName() string {
	return "ivan_scanner_scan_strategies"
}

type Software struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	License         string `json:"license"`
	AbnormalSoft    bool   `json:"abnormalSoft"`
	AbnormalLicense bool   `json:"AbnormalLicense"`
	LayerDigest     string `json:"layerDigest"`
}

func (s *ScanConfig) ToUpdater() map[string]interface{} {
	s.Serialize()
	updater := map[string]interface{}{
		"vuln_flush_trig_enable":        s.VulnFlushTrigEnable,
		"malicious_flush_trig_enable":   s.MaliciousFlushTrigEnable,
		"library_image_config":          s.LibraryImageJson,
		"node_image_config":             s.NodeImageJson,
		"library_image_add_trig_enable": s.LibraryImageAddTrigEnable,
		"node_image_add_trig_enable":    s.NodeImageAddTrigEnable,
	}
	return updater
}

func (s *ScanConfig) Check() error {
	checkTime := func(ti string) error {
		split := strings.Split(ti, ":")
		if len(split) != 2 {
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

	if s.LibraryImageConfig == nil {
		return fmt.Errorf("no scan config for library image")
	}
	if s.NodeImageConfig == nil {
		return fmt.Errorf("no scan config for node image")
	}
	if s.LibraryImageConfig.StrategyID <= 0 {
		return fmt.Errorf("no strategy for library image scan config")
	}
	if s.LibraryImageConfig.StrategyID <= 0 {
		return fmt.Errorf("no strategy for node image scan config")
	}
	for i := range s.NodeImageConfig.ScanCycle {
		if s.NodeImageConfig.ScanCycle[i] < int64(time.Sunday) || s.NodeImageConfig.ScanCycle[i] > int64(time.Saturday) {
			return fmt.Errorf("扫描周期位于周一到周日之间")
		}
	}
	for i := range s.LibraryImageConfig.ScanCycle {
		if s.LibraryImageConfig.ScanCycle[i] < int64(time.Sunday) || s.LibraryImageConfig.ScanCycle[i] > int64(time.Saturday) {
			return fmt.Errorf("扫描周期位于周一到周日之间")
		}
	}
	if s.NodeImageConfig.ScanTime != "" {
		if err := checkTime(s.NodeImageConfig.ScanTime); err != nil {
			return err
		}
	}

	if s.LibraryImageConfig.ScanTime != "" {
		if err := checkTime(s.LibraryImageConfig.ScanTime); err != nil {
			return err
		}
	}

	return nil
}

func (s *ScanConfig) Serialize() {
	if s.LibraryImageConfig != nil {
		bys, err := json.Marshal(s.LibraryImageConfig)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("ScanConfig,Serialize")
		} else {
			s.LibraryImageJson = string(bys)
		}
	}
	if s.NodeImageConfig != nil {
		bys, err := json.Marshal(s.NodeImageConfig)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("ScanConfig,Serialize")
		} else {
			s.NodeImageJson = string(bys)
		}
	}
}

func (s *ScanConfig) Deserialize() {
	if s.LibraryImageJson != "" {
		ll := new(ScanConfigSinge)
		err := json.Unmarshal([]byte(s.LibraryImageJson), ll)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("ScanConfig,Deserialize")
		} else {
			if ll.Libraries == nil {
				ll.Libraries = make([]int64, 0)
			}
			if ll.ScanCycle == nil {
				ll.ScanCycle = make([]int64, 0)
			}

			s.LibraryImageConfig = ll
		}

	}
	if s.NodeImageJson != "" {
		ll := new(ScanConfigSinge)
		err := json.Unmarshal([]byte(s.NodeImageJson), ll)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("ScanConfig,Deserialize")
		} else {
			if len(ll.NodeHostnames) == 0 {
				ll.NodeHostnames = make([]string, 0)
			}
			if len(ll.ScanCycle) == 0 {
				ll.ScanCycle = make([]int64, 0)
			}
			s.NodeImageConfig = ll
		}
	}
}

func (s *Software) Check() error {
	if s.Name == "" {
		return fmt.Errorf("no software name")
	}
	if s.Version == "" {
		return fmt.Errorf("no software version")
	}

	return nil
}

func (s *ScanStrategy) Serialize() {
	if len(s.SensitiveFile) > 0 {
		ses := make([]SensitiveFileScan, 0)
		for i := range s.SensitiveFile {
			if s.SensitiveFile[i].Value != "" {
				ses = append(ses, s.SensitiveFile[i])
			}
		}
		// 设置默认值
		for i := range ses {
			if ses[i].SecretType == "" {
				ses[i].SecretType = "Filename"
			}
		}

		s.SensitiveFile = ses
		if len(ses) > 0 {
			if bys, err := json.Marshal(s.SensitiveFile); err == nil {
				s.SensitiveFileJson = string(bys)
			} else {
				logging.GetLogger().Error().Err(err)
			}
		}
	}
	if len(s.Envs) > 0 {
		s.Envs = DeDuplicateString(s.Envs)

		if bys, err := json.Marshal(s.Envs); err == nil {
			s.EnvsJson = string(bys)
		} else {
			logging.GetLogger().Error().Err(err)
		}
	}
	if len(s.OpenLicense) > 0 {
		s.OpenLicense = DeDuplicateString(s.OpenLicense)
		if bys, err := json.Marshal(s.OpenLicense); err == nil {
			s.OpenLicenseJson = string(bys)
		} else {
			logging.GetLogger().Error().Err(err)
		}
	}
	if len(s.Software) > 0 {
		ans := make([]Software, 0)
		exit := make(map[string]bool)
		for i := range s.Software {
			if !exit[fmt.Sprintf("%s_%s", s.Software[i].Name, s.Software[i].Version)] {
				exit[fmt.Sprintf("%s_%s", s.Software[i].Name, s.Software[i].Version)] = true
				ans = append(ans, s.Software[i])
			}
		}
		s.Software = ans
		if bys, err := json.Marshal(s.Software); err == nil {
			s.SoftwareJson = string(bys)
		} else {
			logging.GetLogger().Error().Err(err)
		}
	}
}

func (s *ScanStrategy) ToUpdater() map[string]interface{} {
	updater := map[string]interface{}{
		"name":                s.Name,
		"operator":            s.Operator,
		"is_default":          s.IsDefault,
		"sensitive_file":      s.SensitiveFileJson,
		"envs":                s.EnvsJson,
		"open_license":        s.OpenLicenseJson,
		"software":            s.SoftwareJson,
		"describe":            s.Describe,
		"envs_enable":         s.EnvsEnable,
		"software_enable":     s.SoftwareEnable,
		"open_license_enable": s.OpenLicenseEnable,
		"sensitive_enable":    s.SensitiveEnable,
		"webshell_enable":     s.WebshellEnable,
		"vul_enable":          s.VulEnable,
		"malicious_enable":    s.MaliciousEnable,
	}
	if len(s.Envs) == 0 {
		updater["envs_enable"] = false
	}
	if len(s.Software) == 0 {
		updater["software_enable"] = false
	}
	return updater
}

func (s *ScanStrategy) Deserialize() {
	st := make([]SensitiveFileScan, 0)
	if len(s.SensitiveFileJson) > 0 {
		if err := json.Unmarshal([]byte(s.SensitiveFileJson), &st); err != nil {
			logging.GetLogger().Error().Err(err)
			st = make([]SensitiveFileScan, 0)
		}
	}
	s.SensitiveFile = st

	envs := make([]string, 0)
	if len(s.EnvsJson) > 0 {
		if err := json.Unmarshal([]byte(s.EnvsJson), &envs); err != nil {
			logging.GetLogger().Error().Err(err)
			envs = make([]string, 0)
		}
	}
	s.Envs = envs

	ops := make([]string, 0)
	if len(s.OpenLicenseJson) > 0 {
		if err := json.Unmarshal([]byte(s.OpenLicenseJson), &ops); err != nil {
			logging.GetLogger().Error().Err(err)
			ops = make([]string, 0)
		}
	}
	s.OpenLicense = ops

	sfs := make([]Software, 0)
	if len(s.SoftwareJson) > 0 {
		if err := json.Unmarshal([]byte(s.SoftwareJson), &sfs); err != nil {
			logging.GetLogger().Error().Err(err)
			sfs = make([]Software, 0)
		}
	}
	s.Software = sfs

}

func (s *ScanStrategy) Check() error {
	if len([]rune(s.Name)) > 50 || s.Name == "" {
		return fmt.Errorf("策略名不超过50个字符且不为空")
	}
	if len([]rune(s.Describe)) > 200 {
		return fmt.Errorf("策略描述不超过200个字符")
	}

	for i := range s.OpenLicense {
		flag := false
		for j := range OpenLicense {
			if s.OpenLicense[i] == OpenLicense[j] {
				flag = true
			}
		}
		if !flag {
			return fmt.Errorf("open license:%s is not allowed", s.OpenLicense[i])
		}
	}
	for i := range s.Software {
		if s.Software[i].Name == "" || s.Software[i].Version == "" {
			return fmt.Errorf("software name or version can not be empty")
		}
	}
	// 敏感文件类型赋默认值
	for i := range s.SensitiveFile {
		if s.SensitiveFile[i].SecretType == "" {
			s.SensitiveFile[i].SecretType = "Filename"
		}
	}

	return nil
}

func (s *ScanStrategy) SetDefault() {
	if len(s.Envs) > 0 {
		s.EnvsEnable = true
	}
	if len(s.Software) > 0 {
		s.SoftwareEnable = true
	}
	if len(s.OpenLicense) > 0 {
		s.OpenLicenseEnable = true
	}
	if len(s.SensitiveFile) > 0 {
		s.SensitiveEnable = true
	}
	// 漏洞，恶义文件,webshell现阶段默认都扫描，前端还没有选项目
	s.VulEnable = true
	s.WebshellEnable = true
	s.MaliciousEnable = true
}

// IsTimeToAddTask 是否到增加任务的时间
func (s *ScanConfig) IsTimeToAddTask(libType int, checkInter int64) (bool, error) {
	check := func(config *ScanConfigSinge, checkInter int64) bool {
		logging.GetLogger().Info().Msgf("AddTaskByStrategy config: %+v", config)

		now := time.Now().UTC().Add(time.Hour * 8)
		week := false
		nowW := now.Weekday()
		logging.GetLogger().Info().Msgf("AddTaskByStrategy,now weekday:%d ,%+v", nowW, config.ScanCycle)
		for i := range config.ScanCycle {
			if config.ScanCycle[i] == int64(nowW) {
				week = true
				break
			}
		}
		if week {
			if config.ScanTime != "" {
				split := strings.Split(config.ScanTime, ":")
				// 上面check函数做了检查
				ho, _ := strconv.ParseInt(split[0], 10, 64)
				mi, _ := strconv.ParseInt(split[1], 10, 64)
				year, month, day := now.Date()
				next := time.Date(year, month, day, int(ho), int(mi), 0, 0, time.UTC).Unix()

				logging.GetLogger().Info().Msgf("AddTaskByStrategy,next:%d,now:%d ", next, now.Unix())
				logging.GetLogger().Info().Msgf("AddTaskByStrategy,next:%s,now:%s ", time.Unix(next, 0).String(), now.String())

				if next-now.Unix() <= checkInter && next-now.Unix() >= 0 {
					return true
				}
			}
		}
		return false
	}

	if err := s.Check(); err != nil {
		return false, err
	}

	if libType == NodeBuffRegistry {
		return check(s.NodeImageConfig, checkInter), nil
	}

	if libType == UserRegistry {
		return check(s.LibraryImageConfig, checkInter), nil
	}
	return false, nil
}

func DeDuplicateString(ss []string) []string {
	ans := make([]string, 0)
	exit := make(map[string]bool)
	for i := range ss {
		if !exit[ss[i]] && ss[i] != "" {
			exit[ss[i]] = true
			ans = append(ans, ss[i])
		}
	}
	return ans
}
