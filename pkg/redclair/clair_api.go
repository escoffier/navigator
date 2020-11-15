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

type cnvdT struct {
	Number      string `json:"cnvdNumber"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	RefLink     string `json:"referenceLink"`
	Description string `json:"desription"` // typo intentional, will fix later, TODO.
}

// "Metadata": {
// 	"NVD": {
// 		"CVSSv2": {
// 			"Score": 7.5,
// 			"Vectors": "AV:N/AC:L/Au:N/C:P/I:P"
// 		}
// 	},
//	"CNVD":[
// 		{
//			"cnvdNumber": "CNVD-2020-19198",
//			"title":"Google Chrome内存错误引用漏洞（CNVD-2020-19198）",
//			"severity":"高",
//			"referenceLink":"https://chromereleases.googleblog.com/2020/03/stable-channel-update-for-desktop_18.html",
//			"desription":"Chrome是由Google开发的一款设计简单、高效的Web浏览工具，其特点是简洁、..."
//		}
//	]
// },
// Example from DB
// metadata     | {"CNVD":[{"cnvdNumber":"CNVD-2020-19198","title":"Google Chrome内存错误引用漏洞（CNVD-2020-19198）","severity":"高",
// "referenceLink":"https://chromereleases.googleblog.com/2020/03/stable-channel-update-for-desktop_18.html",
// "desription":"Chrome是由Google开发的一款设计简单、高效的Web浏览工具，其特点是简洁、快速。\n\nGoogle Chrome 80.0.3987.149之前版本中的audio存在内存错误引用漏洞。远程攻击者可利用该漏洞通过精心制作的HTML页面利用堆破坏。"}],
// "NVD":{"CVSSv2":{"PublishedDateTime":"2020-03-23T16:15Z","Vectors":"AV:N/AC:M/Au:N/C:C/I:C/A:C","Score":9.3},
// "CVSSv3":{"Vectors":"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H","Score":8.8,"ExploitabilityScore":2.8,"ImpactScore":5.9}}}
type metadataT struct {
	NVD  nvdT    `json:"NVD"`
	CNVD []cnvdT `json:"CNVD"`
}
