package scanner

import (
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type ImageScanSummaryResult struct {
	TopVulns        []model.VulnerabilityInfo `json:"topVulnerabilities"`
	OverallSeverity string                    `json:"overallSeverity"`
	Repository      string                    `json:"repository"`
	Tag             string                    `json:"tag"`
	Digest          string                    `json:"digest"`
	TaskID          primitive.ObjectID        `json:"taskID"`
	SensitiveFiles  []model.Sensitive         `json:"sensitiveFiles"`
	StartedAt       int64                     `json:"startedAt"`
	FinishedAt      int64                     `json:"finishedAt"`
}

type ImageScanDetailedResult struct {
	TopVulns        []model.VulnerabilityInfo        `json:"topVulnerabilities"`
	OverallSeverity string                           `json:"overallSeverity"`
	Repository      string                           `json:"repository"`
	Tag             string                           `json:"tag"`
	Digest          string                           `json:"digest"`
	PerLayerReport  []model.VulnerabilityLayerReport `json:"perLayerReport"`
	TaskID          primitive.ObjectID               `json:"taskID"`
}
