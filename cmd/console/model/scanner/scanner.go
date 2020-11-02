package scanner

import (
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
}

type ImageScanDetailedResult struct {
	TopVulns        []redclair.VulnerabilityInfo                 `json:"topVulnerabilities"`
	OverallSeverity string                                       `json:"overallSeverity"`
	Repository      string                                       `json:"repository"`
	Tag             string                                       `json:"tag"`
	Digest          string                                       `json:"digest"`
	PerLayerReport  map[string]redclair.VulnerabilityLayerReport `json:"perLayerReport"`
	TaskID          primitive.ObjectID                           `json:"taskID"`
}
