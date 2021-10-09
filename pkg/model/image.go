package model

import (
	"time"
)

const (
	QUESTION_VULN      = 0
	QUESTION_VIRUS     = 1
	QUESTION_SENSITIVE = 2
	QUESTION_WEB_SHELL = 3

	JobNotScan string = "not_scan"
	// JobPending ...
	JobPending string = "pending"
	// JobRunning ...
	JobRunning string = "running"
	// JobError ...
	JobError string = "error"
	// JobStopped ...
	JobStopped string = "stopped"
	// JobFinished ...
	JobFinished string = "finished"
	// JobCanceled ...
	JobCanceled string = "canceled"
	// JobRetrying indicate the job needs to be retried, it will be scheduled to the end of job queue by statemachine after an interval.
	JobRetrying string = "retrying"
	// JobContinue is the status returned by statehandler to tell statemachine to move to next possible state based on trasition table.
	JobContinue string = "_continue"
	// JobScheduled ...
	JobScheduled string = "scheduled"

	SCANSTAUTS = "scan_status"

	VirusStatusDoing string = "doing"
	VirusStatusWait  string = "wait"
)

type ImageInfo struct {
	ID           int64  `json:"id"`
	Digest       string `json:"digest"`
	FullRepoName string `json:"full_repo_name"`
	Library      string `json:"library"`
	Tags         string `json:"tags"`
}

type QuestionInfo struct {
	QID          int    `gorm:"primary_key;AUTO_INCREMENT" json:"-" `
	ID           int    `gorm:"column:id;index" json:"id"`
	Digest       string `gorm:"column:digest;index" json:"digest,omitempty"`
	LinkObjectId string `gorm:"column:link_object_id" json:"link_object_id,omitempty"` // mongo scantask表的ID
	Time         string `gorm:"column:time" json:"timem,omitempty"`
}

func (q QuestionInfo) TableName() string {
	return "tensor_question"
}

type VirusFileInfo struct {
	Filename  string `json:"filename"`
	Filepath  string `json:"filepath"`
	Virusname string `json:"virusname"`
}

type WebshellFileInfo struct {
	Filename string   `json:"filename"`
	Filepath string   `json:"filepath"`
	Score    int64    `json:"score"`
	Codes    []string `json:"codes"`
}

type Artifacts struct {
	Af2 []Artifacts2
	Af1 []Artifacts1
}

type Artifacts2 struct {
	FullRepoName  string `json:"full_repo_name"`
	AdditionLinks struct {
		BuildHistory struct {
			Absolute bool   `json:"absolute"`
			Href     string `json:"href"`
		} `json:"build_history"`
		Vulnerabilities struct {
			Absolute bool   `json:"absolute"`
			Href     string `json:"href"`
		} `json:"vulnerabilities"`
	} `json:"addition_links"`
	Digest     string `json:"digest"`
	ExtraAttrs struct {
		Architecture string `json:"architecture"`
		Author       string `json:"author"`
		Config       struct {
			Entrypoint []string `json:"Entrypoint"`
			Env        []string `json:"Env"`
			Labels     struct {
				OrgLabelSchemaBuildDate        string `json:"org.label-schema.build-date"`
				OrgLabelSchemaLicense          string `json:"org.label-schema.license"`
				OrgLabelSchemaName             string `json:"org.label-schema.name"`
				OrgLabelSchemaSchemaVersion    string `json:"org.label-schema.schema-version"`
				OrgLabelSchemaVendor           string `json:"org.label-schema.vendor"`
				OrgOpencontainersImageCreated  string `json:"org.opencontainers.image.created"`
				OrgOpencontainersImageLicenses string `json:"org.opencontainers.image.licenses"`
				OrgOpencontainersImageTitle    string `json:"org.opencontainers.image.title"`
				OrgOpencontainersImageVendor   string `json:"org.opencontainers.image.vendor"`
			} `json:"Labels"`
			WorkingDir string `json:"WorkingDir"`
		} `json:"config"`
		Created time.Time `json:"created"`
		Os      string    `json:"os"`
	} `json:"extra_attrs"`
	Icon              string      `json:"icon"`
	ID                int         `json:"id"`
	Labels            interface{} `json:"labels"`
	ManifestMediaType string      `json:"manifest_media_type"`
	MediaType         string      `json:"media_type"`
	ProjectID         int         `json:"project_id"`
	PullTime          time.Time   `json:"pull_time"`
	PushTime          time.Time   `json:"push_time"`
	References        interface{} `json:"references"`
	RepositoryID      int         `json:"repository_id"`
	Size              int         `json:"size"`
	Tags              []struct {
		ArtifactID   int    `json:"artifact_id"`
		ID           int    `json:"id"`
		Immutable    bool   `json:"immutable"`
		Name         string `json:"name"`
		PullTime     string `json:"pull_time"`
		PushTime     string `json:"push_time"`
		RepositoryID int    `json:"repository_id"`
		Signed       bool   `json:"signed"`
	} `json:"tags"`
	Type string `json:"type"`
}

type Artifacts1 struct {
	FullRepoName  string `json:"full_repo_name"`
	Digest        string `json:"digest"`
	Name          string `json:"name"`
	Size          int    `json:"size"`
	Architecture  string `json:"architecture"`
	Os            string `json:"os"`
	OsVersion     string `json:"os.version"`
	DockerVersion string `json:"docker_version"`
	Author        string `json:"author"`
	Created       string `json:"created"`
	Config        struct {
		Labels interface{} `json:"labels"`
	} `json:"config"`
	Immutable bool          `json:"immutable"`
	Signature interface{}   `json:"signature"`
	Labels    []interface{} `json:"labels"`
	PushTime  time.Time     `json:"push_time"`
	PullTime  time.Time     `json:"pull_time"`
}

type OverView struct {
	ImageTotal  int64    `json:"image_total"`
	OnlineTotal int64    `json:"online_total"`
	Sum         SafeOver `json:"sum"`
	Online      SafeOver `json:"online"`
}

type SafeOver struct {
	VULN      int `json:"vuln"`
	VIRUS     int `json:"virus"`
	SENSITIVE int `json:"sensitive"`
	Webshell  int `json:"webshell"`
	Pkg       int `json:"pkg"`
}
