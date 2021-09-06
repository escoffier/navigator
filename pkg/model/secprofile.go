package model

import (
	"time"
)

var commandWhitelistSortableFields = func() map[string]string {
	return map[string]string{
		"command":          "command",
		"workingDirectory": "working_directory",
	}
}

func GetCommandWhitelistSortableField(key string) string {
	return commandWhitelistSortableFields()[key]
}

func GetDefaultCommandWhitelistSortableName() string {
	return "command"
}

func GetCommandWhitelistSortableNames() []string {
	keys := make([]string, len(commandWhitelistSortableFields()))

	i := 0
	for k := range commandWhitelistSortableFields() {
		keys[i] = k
		i++
	}
	return keys
}

var seccompSortableFields = func() map[string]string {
	return map[string]string{
		"syscall": "syscall",
	}
}

func GetSeccompSortableField(key string) string {
	return seccompSortableFields()[key]
}

func GetDefaultSeccompSortableName() string {
	return "syscall"
}

func GetSeccompSortableNames() []string {
	keys := make([]string, len(seccompSortableFields()))

	i := 0
	for k := range seccompSortableFields() {
		keys[i] = k
		i++
	}
	return keys
}

var apparmorSortableFields = func() map[string]string {
	return map[string]string{
		"file":   "file",
		"access": "access",
	}
}

func GetApparmorSortableField(key string) string {
	return apparmorSortableFields()[key]
}

func GetDefaultApparmorSortableName() string {
	return "file"
}

func GetApparmorSortableNames() []string {
	keys := make([]string, len(apparmorSortableFields()))

	i := 0
	for k := range apparmorSortableFields() {
		keys[i] = k
		i++
	}
	return keys
}

var policySortableFields = func() map[string]string {
	return map[string]string{
		"createdAt":   "created_at",
		"updatedAt":   "updated_at",
		"author":      "author",
		"updatedBy":   "updated_by",
		"active":      "active",
		"mode":        "mode",
		"name":        "name",
		"description": "description",
	}
}

func GetPolicySortableField(key string) string {
	return policySortableFields()[key]
}

func GetDefaultPolicySortableName() string {
	return "createdAt"
}

func GetPolicySortableNames() []string {
	keys := make([]string, len(policySortableFields()))

	i := 0
	for k := range policySortableFields() {
		keys[i] = k
		i++
	}
	return keys
}

var resourceSortableFields = func() map[string]string {
	return map[string]string{
		"cluster":       "cluster",
		"namespace":     "namespace",
		"kind":          "kind",
		"name":          "name",
		"containerName": "container_name",
	}
}

func GetResourceSortableField(key string) string {
	return resourceSortableFields()[key]
}

func GetDefaultResourceSortableName() string {
	return "containerName"
}

func GetResourceSortableNames() []string {
	keys := make([]string, len(resourceSortableFields()))

	i := 0
	for k := range resourceSortableFields() {
		keys[i] = k
		i++
	}
	return keys
}

type SecurityMode string

const (
	SecurityModeDetection  SecurityMode = "detection"
	SecurityModePrevention SecurityMode = "prevention"
)

type SecurityKind string

const (
	SecurityKindAny              SecurityKind = "all"
	SecurityKindSeccomp          SecurityKind = "seccomp"
	SecurityKindApparmor         SecurityKind = "apparmor"
	SecurityKindDrift            SecurityKind = "drift"
	SecurityKindCommandWhitelist SecurityKind = "command-whitelist"
)

type SecProfileCommand string

const (
	SecProfileCommandTrainStart     SecProfileCommand = "train_start"
	SecProfileCommandTrainStarted   SecProfileCommand = "train_started"
	SecProfileCommandTrainStop      SecProfileCommand = "train_stop"
	SecProfileCommandTrainStopped   SecProfileCommand = "train_stopped"
	SecProfileCommandTrainAbort     SecProfileCommand = "train_abort"
	SecProfileCommandTrainAborted   SecProfileCommand = "train_aborted"
	SecProfileCommandTrainSuspend   SecProfileCommand = "train_suspend"
	SecProfileCommandTrainSuspended SecProfileCommand = "train_suspended"
	SecProfileCommandInvalidState   SecProfileCommand = "invalid_state"
	SecProfileCommandTrainResume    SecProfileCommand = "train_resume"
	SecProfileCommandTrainResumed   SecProfileCommand = "train_resumed"
	SecProfileCommandTestStart      SecProfileCommand = "test_start"
	SecProfileCommandTestStop       SecProfileCommand = "test_stop"
)

type TrainingStatus string

const (
	TrainingStatusNotStarted TrainingStatus = "no_training"
	TrainingStatusInProgress TrainingStatus = "training_in_progress"
	TrainingStatusPaused     TrainingStatus = "training_paused"
)

type KubernetesResource string

const (
	KubernetesResourcePod         KubernetesResource = "pod"
	KubernetesResourceDeployment  KubernetesResource = "deployment"
	KubernetesResourceStatefulset KubernetesResource = "statefulset"
	KubernetesResourceReplicaSet  KubernetesResource = "replicaset"
	KubernetesResourceDaemonset   KubernetesResource = "daemonset"
	KubernetesResourceJob         KubernetesResource = "job"
	KubernetesResourceCronJob     KubernetesResource = "cronjob"
	KubernetesResourceAny         KubernetesResource = "any"
)

type TrainingStartWhitelistOption string

const (
	TrainingStartWhitelistOptionFromScratch        TrainingStartWhitelistOption = "from_scratch"
	TrainingStartWhitelistOptionFromCurrentProfile TrainingStartWhitelistOption = "from_current_profile"
)

type ResourceImageChangeAction string

const (
	ResourceImageChangeActionChangeToAudit                  ResourceImageChangeAction = "change_to_audit"
	ResourceImageChangeActionPolicyDisable                  ResourceImageChangeAction = "disable_policy"
	ResourceImageChangeActionApplyProfilesToUpdatedResource ResourceImageChangeAction = "apply_profiles_to_updated_resource"
)

const (
	EventProcessorRedisKey = "eventprocessor"
	SecProfileRedisKey     = "secprofile"
)

type SecurityPolicy struct {
	ID                        int                       `gorm:"primary_key;AUTO_INCREMENT" json:"id"`
	Mode                      SecurityMode              `gorm:"column:mode" json:"mode"`
	Name                      string                    `gorm:"index:name,unique;column:name" json:"name"`
	Description               string                    `gorm:"column:description" json:"description"`
	Active                    bool                      `gorm:"column:active" json:"active"`
	CreatedAt                 time.Time                 `gorm:"column:created_at" json:"createdAt"`
	UpdatedAt                 time.Time                 `gorm:"column:updated_at" json:"updatedAt"`
	Author                    string                    `gorm:"column:author" json:"author"`
	UpdatedBy                 string                    `gorm:"column:updated_by" json:"updatedBy"`
	Resources                 []SecurityPolicyResource  `gorm:"foreignKey:SecurityPolicyID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL" json:"resources,omitempty"`
	ApparmorProfile           ApparmorProfile           `gorm:"foreignKey:SecurityPolicyID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL" json:"apparmorProfile,omitempty"`
	SeccompProfile            SeccompProfile            `gorm:"foreignKey:SecurityPolicyID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL" json:"seccompProfile,omitempty"`
	CommandWhitelistProfile   CommandWhitelistProfile   `gorm:"foreignKey:SecurityPolicyID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL" json:"commandWhitelistProfile,omitempty"`
	DriftProfile              DriftProfile              `gorm:"foreignKey:SecurityPolicyID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL" json:"driftProfile,omitempty"`
	ResourceImageChangeAction ResourceImageChangeAction `gorm:"column:resource_image_change_action" json:"resourceImageChangeAction"`
}

type DriftProfile struct {
	SecurityPolicyID *int `json:"-"`
	ID               int  `gorm:"primary_key;AUTO_INCREMENT" json:"id"`
	Enabled          bool `gorm:"enabled" json:"enabled"`
}

type ApparmorProfile struct {
	SecurityPolicyID             int                          `json:"-"`
	ID                           int                          `gorm:"primary_key;AUTO_INCREMENT" json:"-"`
	Enabled                      bool                         `gorm:"enabled" json:"enabled"`
	ApparmorProfileData          []ApparmorProfileData        `gorm:"foreignKey:ApparmorProfileID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL" json:"apparmorProfileData,omitempty"`
	TimeFrame                    int                          `gorm:"column:timeframe" json:"-"`
	TrainingStatus               TrainingStatus               `gorm:"column:training_status" json:"trainingStatus,omitempty"`
	StartTrainingTime            *time.Time                   `gorm:"column:start_training_time" json:"startTrainingTime,omitempty"`
	StopTrainingTime             *time.Time                   `gorm:"column:stop_training_time" json:"stopTrainingTime,omitempty"`
	AbortTrainingTime            *time.Time                   `gorm:"column:abort_training_time" json:"abortTrainingTime,omitempty"`
	SuspendTrainingTime          *time.Time                   `gorm:"column:suspend_training_time" json:"suspendTrainingTime,omitempty"`
	ResumeTrainingTime           *time.Time                   `gorm:"column:resume_training_time" json:"resumeTrainingTime,omitempty"`
	ElapsedTime                  int                          `gorm:"column:elapsed_time" json:"elapsedTime,omitempty"`
	TrainingTimeout              int                          `gorm:"trainingTimeout" json:"trainingTimeout,omitempty"`
	TrainingStartWhitelistOption TrainingStartWhitelistOption `gorm:"trainingStartWhitelistOption" json:"trainingStartWhitelistOption,omitempty"`
}

type CommandWhitelistProfile struct {
	SecurityPolicyID             int                           `json:"-"`
	ID                           int                           `gorm:"primary_key;AUTO_INCREMENT" json:"-"`
	Enabled                      bool                          `gorm:"enabled" json:"enabled"`
	CommandWhitelistProfileData  []CommandWhitelistProfileData `gorm:"foreignKey:CommandWhitelistProfileID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL" json:"commandWhitelistProfileData,omitempty"`
	TimeFrame                    int                           `gorm:"column:timeframe" json:"-"`
	TrainingStatus               TrainingStatus                `gorm:"column:training_status" json:"trainingStatus,omitempty"`
	StartTrainingTime            *time.Time                    `gorm:"column:start_training_time" json:"startTrainingTime,omitempty"`
	StopTrainingTime             *time.Time                    `gorm:"column:stop_training_time" json:"stopTrainingTime,omitempty"`
	AbortTrainingTime            *time.Time                    `gorm:"column:abort_training_time" json:"abortTrainingTime,omitempty"`
	SuspendTrainingTime          *time.Time                    `gorm:"column:suspend_training_time" json:"suspendTrainingTime,omitempty"`
	ResumeTrainingTime           *time.Time                    `gorm:"column:resume_training_time" json:"resumeTrainingTime,omitempty"`
	ElapsedTime                  int                           `gorm:"column:elapsed_time" json:"elapsedTime,omitempty"`
	TrainingTimeout              int                           `gorm:"trainingTimeout" json:"trainingTimeout,omitempty"`
	TrainingStartWhitelistOption TrainingStartWhitelistOption  `gorm:"trainingStartWhitelistOption" json:"trainingStartWhitelistOption,omitempty"`
}

type SeccompProfile struct {
	SecurityPolicyID             int                          `json:"-"`
	ID                           int                          `gorm:"primary_key;AUTO_INCREMENT" json:"-"`
	Enabled                      bool                         `gorm:"enabled" json:"enabled"`
	SeccompProfileData           []SeccompProfileData         `gorm:"foreignKey:SeccompProfileID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL" json:"seccompProfileData,omitempty"`
	TimeFrame                    int                          `gorm:"column:timeframe" json:"-"`
	TrainingStatus               TrainingStatus               `gorm:"column:training_status" json:"trainingStatus,omitempty"`
	StartTrainingTime            *time.Time                   `gorm:"column:start_training_time" json:"startTrainingTime,omitempty"`
	StopTrainingTime             *time.Time                   `gorm:"column:stop_training_time" json:"stopTrainingTime,omitempty"`
	AbortTrainingTime            *time.Time                   `gorm:"column:abort_training_time" json:"abortTrainingTime,omitempty"`
	SuspendTrainingTime          *time.Time                   `gorm:"column:suspend_training_time" json:"suspendTrainingTime,omitempty"`
	ResumeTrainingTime           *time.Time                   `gorm:"column:resume_training_time" json:"resumeTrainingTime,omitempty"`
	ElapsedTime                  int                          `gorm:"column:elapsed_time" json:"elapsedTime,omitempty"`
	TrainingTimeout              int                          `gorm:"trainingTimeout" json:"trainingTimeout,omitempty"`
	TrainingStartWhitelistOption TrainingStartWhitelistOption `gorm:"trainingStartWhitelistOption" json:"trainingStartWhitelistOption,omitempty"`
}

type SeccompProfileData struct {
	SeccompProfileID int    `json:"-"`
	Syscall          string `gorm:"column:syscall" json:"syscall"`
}

type ApparmorProfileData struct {
	ApparmorProfileID int    `json:"-"`
	File              string `gorm:"column:file" json:"file"`
	Access            string `gorm:"column:access" json:"access"`
}

type CommandWhitelistProfileData struct {
	CommandWhitelistProfileID int    `json:"-"`
	Command                   string `gorm:"column:command" json:"command"`
	WorkingDirectory          string `gorm:"column:working_directory" json:"workingDirectory"`
}

type SecurityPolicyAddRequest struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
}

type SecurityPolicyPutRequest struct {
	Name                      *string                    `json:"name"`
	Description               *string                    `json:"description"`
	ResourceImageChangeAction *ResourceImageChangeAction `json:"resourceImageChangeAction"`
}

type SecurityPolicyProfilePutRequest struct {
	Enabled                      *bool                         `json:"enabled"`
	Timeout                      *int                          `json:"timeout"`
	TrainingStartWhitelistOption *TrainingStartWhitelistOption `json:"trainingStartWhitelistOption"`
}

type SecurityPolicyResource struct {
	SecurityPolicyID *int               `json:"-"`
	ID               int                `gorm:"primary_key;AUTO_INCREMENT" json:"id"`
	Cluster          string             `gorm:"column:cluster" json:"cluster"`
	Name             string             `gorm:"column:name" json:"name"`
	Kind             KubernetesResource `gorm:"column:kind" json:"kind"`
	Namespace        string             `gorm:"column:namespace" json:"namespace"`
	ContainerName    string             `gorm:"container_name" json:"containerName"`
	ImageRegistry    string             `gorm:"image_registry" json:"imageRegistry"`
	ImageName        string             `gorm:"image_name" json:"imageName"`
	ImageTag         string             `gorm:"image_tag" json:"imageTag"`
}

type SecProfileIntermediate struct {
	SecProfileEnvelope   *SecProfileEnvelope
	Whitelist            []string  `json:"whitelist"`
	Timeout              int       `json:"timeout"`
	TimeFrame            int       `json:"timeframe"`
	EventPerTimeFrame    int       `json:"eventsPerTimeFrame"`
	NewEventsInTimeFrame int       `json:"newEventsInTimeFrame"`
	Paused               bool      `json:"paused"`
	ElapsedTime          int       `json:"elapsedTime"`
	StartTime            time.Time `json:"startTime"`
	PolicyID             int       `json:"policyID"`
}

type ContainerInfo struct {
	ContainerName string `json:"containerName"`
	ImageRegistry string `json:"imageRegistry"`
	ImageName     string `json:"imageName"`
	ImageTag      string `json:"imageTag"`
}

type SecProfileEnvelope struct {
	Kind                        SecurityKind                  `json:"kind"`
	Name                        string                        `json:"name"`
	ApparmorProfileData         []ApparmorProfileData         `json:"apparmorProfileData,omitempty"`
	SeccompProfileData          []SeccompProfileData          `json:"seccompProfileData,omitempty"`
	CommandWhitelistProfileData []CommandWhitelistProfileData `json:"commandWhitelistProfileData,omitempty"`
	Mode                        SecurityMode                  `json:"mode"`
}

type SecurityProfileCommand struct {
	Command           SecProfileCommand        `json:"command"`
	Resources         []SecurityPolicyResource `json:"resources"`
	PolicyID          int                      `json:"policyID"`
	Kind              SecurityKind             `json:"kind"`
	Whitelist         []string                 `json:"whitelist"`
	Timeout           int                      `json:"timeout"`
	TimeFrame         int                      `json:"timeframe"`
	EventPerTimeFrame int                      `json:"eventsPerTimeFrame"`
	StartTime         time.Time                `json:"startTime"`
	UpdatedBy         string                   `json:"updatedBy"`
}

type SeccompAuditLogEntry struct {
	Syscall     int       `json:"syscall"`
	SyscallName string    `json:"syscallName"`
	Pid         int       `json:"pid"`
	Action      string    `json:"action"`
	Timestamp   time.Time `json:"time"`
}

type ApparmorAuditLogEntry struct {
	Profile       string    `json:"profile"`
	RequestedFlag string    `json:"requestedFlag"`
	Operation     string    `json:"operation"`
	Action        string    `json:"action"`
	Name          string    `json:"name"`
	Pid           int       `json:"pid"`
	Timestamp     time.Time `json:"time"`
}

type ProfileData struct {
	SeccompProfileData          []SeccompProfileData          `json:"seccompProfileData,omitempty"`
	ApparmorProfileData         []ApparmorProfileData         `json:"apparmorProfileData,omitempty"`
	CommandWhitelistProfileData []CommandWhitelistProfileData `json:"commandWhitelistProfileData,omitempty"`
}

type ProfileDataPost struct {
	SeccompProfileDataAdd             []SeccompProfileData          `json:"addSeccompProfileData,omitempty"`
	ApparmorProfileDataAdd            []ApparmorProfileData         `json:"addApparmorProfileData,omitempty"`
	CommandWhitelistProfileDataAdd    []CommandWhitelistProfileData `json:"addCommandWhitelistProfileData,omitempty"`
	SeccompProfileDataRemove          []SeccompProfileData          `json:"removeSeccompProfileData,omitempty"`
	ApparmorProfileDataRemove         []ApparmorProfileData         `json:"removeApparmorProfileData,omitempty"`
	CommandWhitelistProfileDataRemove []CommandWhitelistProfileData `json:"removeCommandWhitelistProfileData,omitempty"`
}

type SecurityPolicyStatusChangeRequest struct {
	Enabled *bool `json:"enabled"`
}

type SecurityPolicyModeChangeRequest struct {
	Mode *SecurityMode `json:"mode"`
}
