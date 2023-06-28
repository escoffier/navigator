package scapper

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"time"

	"github.com/shopspring/decimal"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/cis/check"
	"gitlab.com/security-rd/go-pkg/logging"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type RecvScanResultReq struct {
	Status     int                       `json:"status"`
	Message    string                    `json:"message"`
	CheckType  model.ComplianceCheckType `json:"checkType"`
	TaskID     string                    `json:"taskID"`
	Hostname   string                    `json:"hostname"`
	ClusterKey string                    `json:"clusterKey"`
	Payload    json.RawMessage           `json:"payload"`
}

type ScanDecoder interface {
	Decode(payload json.RawMessage) error
	BuildResult(taskId, hostname, clusterKey string) []*model.ScanResult
	FillScanNodeRecord(record *model.ScanNodeRecord)
}

type kube struct {
	AutoVariate datatypes.JSON    `json:"autoVariate"`
	Controls    []*check.Controls `json:"controls"`
	Totals      check.Summary     `json:"totals"`
}

func (k *kube) Decode(payload json.RawMessage) error {
	return json.Unmarshal(payload, k)
}

func (k *kube) BuildResult(taskId, hostname, clusterKey string) []*model.ScanResult {
	ctx := context.Background()
	svc, _ := GetService(ctx)
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

	passRate := float64(record.Pass+record.Warn+record.Info) /
		float64(record.Pass+record.Warn+record.Info+record.Fail)
	if !math.IsNaN(passRate) {
		record.PassRate = decimal.NewFromFloat(passRate)
	} else {
		record.PassRate = decimal.Zero
	}
}

type cri struct {
	Controls *check.Controls `json:"control"`
}

func (c *cri) Decode(payload json.RawMessage) error {
	return json.Unmarshal(payload, c)
}

func (c *cri) BuildResult(taskId, hostname, clusterKey string) []*model.ScanResult {
	ctx := context.Background()
	svc, _ := GetService(ctx)
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
	record.Pass = c.Controls.Pass
	record.Warn = c.Controls.Warn
	record.Info = c.Controls.Info
	record.Fail = c.Controls.Fail

	passRate := float64(record.Pass+record.Warn+record.Info) /
		float64(record.Pass+record.Warn+record.Info+record.Fail)
	if !math.IsNaN(passRate) {
		record.PassRate = decimal.NewFromFloat(passRate)
	} else {
		record.PassRate = decimal.Zero
	}
}

type host struct {
	Controls *check.Controls `json:"control"`
}

func (h *host) Decode(payload json.RawMessage) error {
	return json.Unmarshal(payload, h)
}

func (h *host) BuildResult(taskId, hostname, clusterKey string) []*model.ScanResult {
	ctx := context.Background()
	svc, _ := GetService(ctx)
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
	record.Pass = h.Controls.Pass
	record.Warn = h.Controls.Warn
	record.Info = h.Controls.Info
	record.Fail = h.Controls.Fail

	passRate := float64(record.Pass+record.Warn+record.Info) /
		float64(record.Pass+record.Warn+record.Info+record.Fail)
	if !math.IsNaN(passRate) {
		record.PassRate = decimal.NewFromFloat(passRate)
	} else {
		record.PassRate = decimal.Zero
	}
}

func RecvScanResults(ctx context.Context, db *gorm.DB, req *RecvScanResultReq) error {
	// logging.Get().Debug().RawJSON("payload", req.Payload).Msg("RecvScanResults")

	logging.Get().Info().Str("taskId", req.TaskID).
		Str("nodeName", req.Hostname).
		Str("checkType", string(req.CheckType)).
		Msgf("add scap scan result")

	// --
	var (
		scanRecord = &model.ScanNodeRecord{
			FinishedAt: time.Now().Unix(),
		}
		items []*model.ScanResult
	)

	if req.Status != 0 { // failed
		scanRecord.State = model.ScanStateFailed
		scanRecord.Message = req.Message
	} else {
		scanRecord.State = model.ScanStateCompleted
		scanRecord.Message = "success"

		var scanDecoder ScanDecoder
		switch req.CheckType {
		case model.ComplianceCheckTargetTypeKube:
			scanDecoder = &kube{}
		case model.ComplianceCheckTargetTypeCRI:
			scanDecoder = &cri{}
		case model.ComplianceCheckTargetTypeHost:
			scanDecoder = &host{}
		default:
			return fmt.Errorf("暂时还不支持的类型: %s", req.CheckType)
		}

		if err := scanDecoder.Decode(req.Payload); err != nil {
			logging.Get().Error().Err(err).Str("checkType", string(req.CheckType)).Msg("scanDecoder.Decode failed")
			return err
		}

		items = scanDecoder.BuildResult(req.TaskID, req.Hostname, req.ClusterKey)
		scanDecoder.FillScanNodeRecord(scanRecord)
	}

	err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if len(items) > 0 {
			err := tx.Model(&model.ScanResult{}).CreateInBatches(items, 100).Error
			if err != nil {
				return err
			}
		}

		// 收到扫描结果将对应任务设置为完成
		return tx.Model(scanRecord).
			Select("state", "finished_at", "message", "auto_variate", "pass", "warn", "info", "fail", "pass_rate").
			Where("state = ?", model.ScanStateInProgress).
			Where("node_name = ? and task_id = ?", req.Hostname, req.TaskID).
			Updates(scanRecord).Error
	})

	if err != nil {
		logging.Get().Err(err).Str("taskId", req.TaskID).
			Str("nodeName", req.Hostname).
			Str("checkType", string(req.CheckType)).
			Msg("接受 扫描结果 数据失败")
	}

	return err
}
