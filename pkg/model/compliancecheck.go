package model

import (
	"database/sql/driver"
	"fmt"
)

type ComplianceCheckType string
type ScanState uint8

func (t ComplianceCheckType) IsValid() bool {
	return t == ComplianceCheckTargetTypeKube ||
		t == ComplianceCheckTargetTypeDocker ||
		t == ComplianceCheckTargetTypeHost
}

func (s *ScanState) Scan(value interface{}) error {
	if t, ok := value.(int64); ok && t >= 0 && t <= 3 {
		*s = ScanState(t)
		return nil
	} else {
		return fmt.Errorf("invaild ScanState: %v", value)
	}
}

func (s ScanState) Value() (driver.Value, error) {
	switch s {
	case ScanStateCompleted, ScanStateInProgress, ScanStateFailed, ScanStateUnknown:
		return int64(s), nil
	default:
		return nil, fmt.Errorf("invalid scan state value: %v", s)
	}
}

type ScapScanResultStateType string

const (
	ScanStateInProgress ScanState = 0
	ScanStateCompleted  ScanState = 1
	ScanStateFailed     ScanState = 2
	ScanStateUnknown    ScanState = 3

	ComplianceCheckTargetTypeKube ComplianceCheckType = "kube"

	// Deprecated: fixme@lilin 后续会全部替换为成CRI，docker不再是一个type
	ComplianceCheckTargetTypeDocker ComplianceCheckType = "docker"
	ComplianceCheckTargetTypeCRI    ComplianceCheckType = "cri"
	ComplianceCheckTargetTypeHost   ComplianceCheckType = "host"

	ScapScanResultStatePASS ScapScanResultStateType = "PASS"
	ScapScanResultStateWARN ScapScanResultStateType = "WARN"
	ScapScanResultStateINFO ScapScanResultStateType = "INFO"
	ScapScanResultStateFAIL ScapScanResultStateType = "FAIL"
)
