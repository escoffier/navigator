package scap

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/shopspring/decimal"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/scapper"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/logging"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type ScanDecoder interface {
	Decode(payload json.RawMessage) error
	BuildResult(taskId, hostname, clusterKey string) []*model.ScanResult
	FillScanNodeRecord(record *model.ScanNodeRecord)
}

type kube struct {
	AutoVariate datatypes.JSON `json:"autoVariate"`
	Controls    []*Controls    `json:"controls"`
	Totals      Summary        `json:"totals"`
}

func (k *kube) Decode(payload json.RawMessage) error {
	return json.Unmarshal(payload, k)
}

func (k *kube) BuildResult(taskId, hostname, clusterKey string) []*model.ScanResult {
	ctx := context.Background()
	svc, _ := scapper.GetService(ctx)
	checkType := model.ComplianceCheckTargetTypeKube
	items := make([]*model.ScanResult, 0)

	for _, control := range k.Controls {
		for _, grooup := range control.Groups {
			for _, check := range grooup.Checks {
				tmp := &model.ScanResult{
					TaskID:      taskId,
					CheckType:   checkType,
					NodeName:    hostname,
					ClusterKey:  clusterKey,
					PolicyID:    check.ID,
					State:       model.ScapScanResultStateType(check.State),
					ActualValue: check.ActualValue,
					UDBCP:       svc.GetUDBCPMap(lang.LanguageZH, check.ID, checkType), // TODO: 这个有问题,zh
					CreatedAt:   time.Now().Unix(),
				}

				policy, err := svc.GetPolicyInfo(ctx, check.ID, checkType)
				if err == nil {
					tmp.Section = policy.TitleZh
				}
				items = append(items, tmp)
			}
		}
	}

	return items
}

func (k *kube) FillScanNodeRecord(record *model.ScanNodeRecord) {
	record.AutoVariate = k.AutoVariate
	record.Pass = k.Totals.Pass
	record.Warn = k.Totals.Warn
	record.Info = k.Totals.Info
	record.Fail = k.Totals.Fail
	record.PassRate = decimal.NewFromFloat(
		float64(record.Pass+record.Warn+record.Info) /
			float64(record.Pass+record.Warn+record.Info+record.Fail))
}

type cri struct {
	AutoVariate datatypes.JSON `json:"autoVariate"`
	Controls    *Controls      `json:"control"`
}

func (c *cri) Decode(payload json.RawMessage) error {
	return json.Unmarshal(payload, c)
}

func (c *cri) BuildResult(taskId, hostname, clusterKey string) []*model.ScanResult {
	ctx := context.Background()
	svc, _ := scapper.GetService(ctx)
	checkType := model.ComplianceCheckTargetTypeDocker
	items := make([]*model.ScanResult, 0)

	for _, grooup := range c.Controls.Groups {
		for _, check := range grooup.Checks {
			// 避免数据过长，无法写入db
			if len(check.ActualValue) > 65535 {
				check.ActualValue = check.ActualValue[:65535]
			}

			tmp := &model.ScanResult{
				TaskID:      taskId,
				CheckType:   checkType,
				NodeName:    hostname,
				ClusterKey:  clusterKey,
				PolicyID:    check.ID,
				State:       model.ScapScanResultStateType(check.State),
				ActualValue: check.ActualValue,
				UDBCP:       svc.GetUDBCPMap(lang.LanguageZH, check.ID, checkType), // TODO: 这个有问题,zh
				CreatedAt:   time.Now().Unix(),
			}

			policy, err := svc.GetPolicyInfo(ctx, check.ID, checkType)
			if err == nil {
				tmp.Section = policy.TitleZh
			}
			items = append(items, tmp)
		}
	}

	return items
}

func (c *cri) FillScanNodeRecord(record *model.ScanNodeRecord) {
	record.AutoVariate = c.AutoVariate
	record.Pass = c.Controls.Pass
	record.Warn = c.Controls.Warn
	record.Info = c.Controls.Info
	record.Fail = c.Controls.Fail
	record.PassRate = decimal.NewFromFloat(
		float64(record.Pass+record.Warn+record.Info) /
			float64(record.Pass+record.Warn+record.Info+record.Fail))
}

type host struct {
	AutoVariate datatypes.JSON `json:"autoVariate"`
	Controls    *Controls      `json:"control"`
}

func (h *host) Decode(payload json.RawMessage) error {
	return json.Unmarshal(payload, h)
}

func (h *host) BuildResult(taskId, hostname, clusterKey string) []*model.ScanResult {
	ctx := context.Background()
	svc, _ := scapper.GetService(ctx)
	checkType := model.ComplianceCheckTargetTypeHost
	items := make([]*model.ScanResult, 0)

	for _, grooup := range h.Controls.Groups {
		for _, check := range grooup.Checks {
			tmp := &model.ScanResult{
				TaskID:      taskId,
				CheckType:   checkType,
				NodeName:    hostname,
				ClusterKey:  clusterKey,
				PolicyID:    check.ID,
				State:       model.ScapScanResultStateType(check.State),
				ActualValue: check.ActualValue,
				UDBCP:       svc.GetUDBCPMap(lang.LanguageZH, check.ID, checkType), // TODO: 这个有问题,zh
				CreatedAt:   time.Now().Unix(),
			}

			policy, err := svc.GetPolicyInfo(ctx, check.ID, checkType)
			if err == nil {
				tmp.Section = policy.TitleZh
			}
			items = append(items, tmp)
		}
	}

	return items
}

func (h *host) FillScanNodeRecord(record *model.ScanNodeRecord) {
	record.AutoVariate = h.AutoVariate
	record.Pass = h.Controls.Pass
	record.Warn = h.Controls.Warn
	record.Info = h.Controls.Info
	record.Fail = h.Controls.Fail
	record.PassRate = decimal.NewFromFloat(
		float64(record.Pass+record.Warn+record.Info) /
			float64(record.Pass+record.Warn+record.Info+record.Fail))
}

// Controls holds all controls to check for master nodes.
type Controls struct {
	ID              string   `yaml:"id" json:"id"`
	Version         string   `json:"version"`
	DetectedVersion string   `json:"detected_version,omitempty"`
	Text            string   `json:"text"`
	Type            string   `json:"node_type"`
	Groups          []*Group `json:"tests"`
	Summary
}

// Group is a collection of similar checks.
type Group struct {
	ID     string   `yaml:"id" json:"section"`
	Type   string   `yaml:"type" json:"type"`
	Pass   int      `json:"pass"`
	Fail   int      `json:"fail"`
	Warn   int      `json:"warn"`
	Info   int      `json:"info"`
	Text   string   `json:"desc"`
	Checks []*Check `json:"results"`
}

// Check contains information about a recommendation in the
// CIS Kubernetes document.
type Check struct {
	ID          string `json:"test_number"`
	Text        string `json:"test_desc"`
	State       string `json:"status"`
	ActualValue string `json:"actual_value"`
	Reason      string `json:"reason,omitempty"`
}

// Summary is a summary of the results of control checks run.
type Summary struct {
	Pass int `json:"total_pass"`
	Fail int `json:"total_fail"`
	Warn int `json:"total_warn"`
	Info int `json:"total_info"`
}

func CallbackScanResults(ctx context.Context, db *gorm.DB, checkType model.ComplianceCheckType, taskId, hostname, clusterKey string, payload json.RawMessage) error {
	logging.Get().Debug().RawJSON("payload", payload).Msg("CallbackScanResults")

	logging.Get().Info().Str("taskId", taskId).
		Str("nodeName", hostname).
		Str("checkType", string(checkType)).
		Msgf("add scap scan result")

	// --
	scanRecord := &model.ScanNodeRecord{
		State:      model.ScanStateCompleted,
		FinishedAt: time.Now().Unix(),
		Message:    "success",
	}

	var scanDecoder ScanDecoder
	switch checkType {
	case model.ComplianceCheckTargetTypeKube:
		scanDecoder = &kube{}
	case model.ComplianceCheckTargetTypeCRI:
		scanDecoder = &cri{}
	case model.ComplianceCheckTargetTypeHost:
		scanDecoder = &host{}
	default:
		return fmt.Errorf("暂时还不支持的类型: %s", checkType)
	}

	if err := scanDecoder.Decode(payload); err != nil {
		logging.Get().Error().Err(err).Str("checkType", string(checkType)).Msg("scanDecoder.Decode failed")
		return err
	}

	items := scanDecoder.BuildResult(taskId, hostname, clusterKey)
	scanDecoder.FillScanNodeRecord(scanRecord)

	err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		err := tx.Model(&model.ScanResult{}).CreateInBatches(items, 100).Error
		if err != nil {
			return err
		}

		// 收到扫描结果将对应任务设置为完成
		return tx.Model(scanRecord).
			Select("state", "finished_at", "message", "auto_variate", "pass", "warn", "info", "fail", "pass_rate").
			Where("state = ?", model.ScanStateInProgress).
			Where("node_name = ? and task_id = ?", hostname, taskId).
			Updates(scanRecord).Error
	})

	if err != nil {
		logging.Get().Err(err).Str("taskId", taskId).
			Str("nodeName", hostname).
			Str("checkType", string(checkType)).
			Msg("添加 扫描结果 数据失败")
	}

	return err
}
