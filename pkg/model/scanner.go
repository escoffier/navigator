package model

// SoftwareType ...
type SoftwareType string

// SourcePackage ...
const SourcePackage SoftwareType = "source"

// BinaryPackage ...
const BinaryPackage SoftwareType = "binary"

// NpmPackage ...
const NpmPackage SoftwareType = "npm"

// InfoPackage ...
const InfoPackage SoftwareType = "info"

// Software ...
type Software struct {
	Name          string       `json:"name"`
	Version       string       `json:"version"`
	VersionFormat string       `json:"versionFormat"`
	Type          SoftwareType `json:"type"`
}

// Sensitive ...
type Sensitive struct {
	Name          string `json:"name" bson:"name"`
	Description   string `json:"description" bson:"description"`
	DescriptionEn string `json:"description_en" bson:"description_en"`
	DescriptionZh string `json:"description_zh" bson:"description_zh"`
}
