package scanner

import (
	"context"

	"gitlab.com/piccolo_su/vegeta/pkg/redclair"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type ImageScanSummaryResult struct {
	TopVulns        []redclair.VulnerabilityInfo `json:"topVulnerabilities"`
	OverallSeverity string                       `json:"overallSeverity"`
	Repository      string                       `json:"repository"`
	Tag             string                       `json:"tag"`
	Digest          string                       `json:"digest"`
	TaskID          primitive.ObjectID           `json:"taskID"`
	SensitiveFiles  []redclair.Sensitive         `json:"sensitiveFiles"`
}

func (issr *ImageScanSummaryResult) ApplyTranslation(ctx context.Context) {
	for i := range issr.TopVulns {
		issr.TopVulns[i].ApplyTranslation(ctx)
	}
	for i := range issr.SensitiveFiles {
		issr.SensitiveFiles[i].ApplyTranslation(ctx)
	}
}

type ImageScanDetailedResult struct {
	TopVulns        []redclair.VulnerabilityInfo        `json:"topVulnerabilities"`
	OverallSeverity string                              `json:"overallSeverity"`
	Repository      string                              `json:"repository"`
	Tag             string                              `json:"tag"`
	Digest          string                              `json:"digest"`
	PerLayerReport  []redclair.VulnerabilityLayerReport `json:"perLayerReport"`
	TaskID          primitive.ObjectID                  `json:"taskID"`
}

func (isdr *ImageScanDetailedResult) ApplyTranslation(ctx context.Context) {
	for i := range isdr.TopVulns {
		isdr.TopVulns[i].ApplyTranslation(ctx)
	}
	for i := range isdr.PerLayerReport {
		isdr.PerLayerReport[i].ApplyTranslation(ctx)
	}
}
