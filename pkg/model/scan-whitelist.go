package model

import (
	"time"

	filecheck "gitlab.com/piccolo_su/vegeta/cmd/file-checker"
)

type ScanWhitelist struct {
	ID            int64                     `gorm:"column:id" json:"id"`
	Digest        string                    `gorm:"column:digest" json:"digest"`
	CreatedAt     time.Time                 `gorm:"column:created_at" json:"created_at"`
	UpdatedAt     time.Time                 `gorm:"column:updated_at" json:"updated_at"`
	WhitelistJSON []byte                    `gorm:"column:whitelist" json:"whitelist"`
	Whitelists    []filecheck.WhitelistFile `gorm:"-" json:"whitelists"`
}

func (w *ScanWhitelist) TableName() string {
	return "ivan_scanner_bin_whitelist"
}
