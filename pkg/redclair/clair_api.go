package redclair

import "encoding/json"

// NewerLayerFeaturesVulnerability New layer feature
type NewerLayerFeaturesVulnerability struct {
	Name          string          `json:"Name,omitempty"`
	NamespaceName string          `json:"NamespaceName,omitempty"`
	Description   string          `json:"Description,omitempty"`
	Link          string          `json:"Link,omitempty"`
	Severity      string          `json:"Severity,omitempty"`
	FixedBy       string          `json:"FixedBy,omitempty"`
	Metadata      json.RawMessage `json:"Metadata,omitempty"`
}

// NewerLayerFeature New Layer feature
type NewerLayerFeature struct {
	Name            string
	NamespaceName   string
	VersionFormat   string
	Version         string
	AddedBy         string
	Vulnerabilities []NewerLayerFeaturesVulnerability
}

// NewerLayer New Layer of image
type NewerLayer struct {
	Name          string
	Path          string
	ParentName    string
	Format        string
	NamespaceName string
	Features      []NewerLayerFeature
}

// ClairEnvelopeError Envelop error
type ClairEnvelopeError struct {
	Message string
}

// NewerLayerEnvelope Newer Layer Envelop
type NewerLayerEnvelope struct {
	Layer NewerLayer
	Error *ClairEnvelopeError
}

type cvssV2T struct {
	PublishedDateTime string      `json:"PublishedDateTime"`
	Vectors           string      `json:"Vectors"`
	Score             json.Number `json:"Score"`
}

type cvssV3T struct {
	Vectors             string      `json:"Vectors"`
	Score               json.Number `json:"Score"`
	ExploitabilityScore json.Number `json:"ExploitabilityScore"`
	ImpactScore         json.Number `json:"ImpactScore"`
}

type nvdT struct {
	CVSSv2 cvssV2T `json:"CVSSv2"`
	CVSSv3 cvssV3T `json:"CVSSv3"`
}

// "Metadata": {
// 	"NVD": {
// 		"CVSSv2": {
// 			"Score": 7.5,
// 			"Vectors": "AV:N/AC:L/Au:N/C:P/I:P"
// 		}
// 	}
// },
// From database, example with CVSSv3:
// metadata     | {"NVD":{"CVSSv2":{"PublishedDateTime":"2020-09-27T04:15Z","Vectors":"AV:N/AC:L/Au:N/C:P/I:P/A:N","Score":6.4},
// "CVSSv3":{"Vectors":"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N","Score":7.2,"ExploitabilityScore":3.9,"ImpactScore":2.7}}}
type metadataT struct {
	NVD nvdT `json:"NVD"`
}
