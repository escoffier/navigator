package scap

import (
	"context"
	"errors"
	"time"

	json "github.com/json-iterator/go"
	"github.com/shopspring/decimal"
	"gitlab.com/piccolo_su/vegeta/cmd/console/service/scapper"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/logging"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type KubeScanResult struct {
	AutoVariate datatypes.JSON `json:"autoVariate"`
	Controls    []*Controls    `json:"controls"`
	Totals      Summary        `json:"totals"`
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
	ID             string `json:"test_number"`
	Text           string `json:"test_desc"`
	Audit          string `json:"audit"`
	AuditEnv       string
	AuditConfig    string
	Type           string   `json:"type"`
	Remediation    string   `json:"remediation"`
	TestInfo       []string `json:"test_info"`
	State          string   `json:"status"`
	ActualValue    string   `json:"actual_value"`
	Scored         bool     `json:"scored"`
	IsMultiple     bool
	ExpectedResult string `json:"expected_result"`
	Reason         string `json:"reason,omitempty"`
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
	items := make([]*model.ScanResult, 0)
	scanRecord := &model.ScanNodeRecord{
		State:      model.ScanStateCompleted,
		FinishedAt: time.Now().Unix(),
		Message:    "success",
	}

	if checkType == model.ComplianceCheckTargetTypeKube {
		checkRet := KubeScanResult{}
		if err := json.Unmarshal(payload, &checkRet); err != nil {
			logging.Get().Error().Err(err).Str("checkType", string(checkType)).Msg("KubeXxxx")
			return err
		}

		svc, _ := scapper.GetService(ctx)

		for _, control := range checkRet.Controls {
			for _, grooup := range control.Groups {
				for _, check := range grooup.Checks {
					tmp := &model.ScanResult{
						TaskID:        taskId,
						CheckType:     checkType,
						NodeName:      hostname,
						ClusterKey:    clusterKey,
						PolicyID:      check.ID,
						State:         model.ScapScanResultStateType(check.State),
						ActualValue:   check.ActualValue,
						RemediationEn: check.Remediation,
						UDBCP:         svc.GetUDBCPMap(lang.LanguageZH, check.ID, checkType),
						CreatedAt:     time.Now().Unix(),
					}

					policy, err := svc.GetPolicyInfo(ctx, check.ID, checkType)
					if err == nil {
						tmp.Section = policy.TitleZh
					}
					items = append(items, tmp)
				}
			}
		}

		scanRecord.AutoVariate = checkRet.AutoVariate
		scanRecord.Pass = checkRet.Totals.Pass
		scanRecord.Warn = checkRet.Totals.Warn
		scanRecord.Info = checkRet.Totals.Info
		scanRecord.Fail = checkRet.Totals.Fail
		scanRecord.PassRate = decimal.NewFromFloat(
			float64(scanRecord.Pass+scanRecord.Warn+scanRecord.Info) /
				float64(scanRecord.Pass+scanRecord.Warn+scanRecord.Info+scanRecord.Fail))
	} else {
		return errors.New("暂时还不支持的类型")
	}

	err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		err := tx.Model(&model.ScanResult{}).CreateInBatches(items, 1000).Error
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
