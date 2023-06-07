package types

import (
	imagesec2 "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type NotifyEventType string

const (
	NotifyEventTypeVulnDBUpdate   NotifyEventType = "vuln-db-update"
	NotifyEventTypeAviraDBUpdate  NotifyEventType = "avira-db-update"
	NotifyEventTypeConfigModified NotifyEventType = "config-modified"
)

type NotifyEvent struct {
	Type            NotifyEventType
	NodeImageConfig imagesec2.NodeImageConfig
}
