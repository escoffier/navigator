package model

import "time"

// MetadataEntry ...
type MetadataEntry struct {
	HistoricisedTimestamp time.Time `json:"-" bson:"historicised_timestamp,omitempty"`
}
