package model

const (
	BehaviorConfigMapLabel                      = "app=behavior-learn-cm"
	SubjectOfBehavioralLearnEvent               = "behavioral_learn_signals"
	BehavioralLearnConfigMapName                = "behavioral-learn"
	BehavioralLearnConfigMapKeyTemplate         = "behavioral-learn-%d"
	BehavioralLearnConfigMapValueTemplate       = "%s/%s/%s/%s/%d/%d/%d" //ClusterKey,Namespace,ResourceKind,Resource,Status,StartTimestamp,EndTimestamp
	BehavioralLearnConfigMapValueDelimiter      = "/"
	BehavioralLearnModelConfigMapNameTemplate   = "bl-model-%d"
	BehavioralLearnWhitelistName                = "bl-whitelist"
	BehavioralLearnFileModelKeyTemplate         = "file-%d"
	BehavioralLearnFileModelValueTemplate       = "%s:%d:%s" // path, permission, container_name
	BehavioralLearnCommandModelKeyTemplate      = "command-%d"
	BehavioralLearnCommandModelValueTemplate    = "%s:%s:%s" // command, user, container_name
	BehavioralLearnNetworkModelKeyTemplate      = "network-%d"
	BehavioralLearnNetworkModelValueTemplate    = "%s:%s:%s:%s:%d:%d:%s:%s" // clusterKey, kind, namespace, name, port, stream_direction,container_name, process_name
	BehavioralLearnCommandModelWlsValueTemplate = "%s:%s:%s"                // path, command, user
	BehavioralLearnFileModelWlsValueTemplate    = "%s:%d"                   // path, permission
	BehavioralLearnNetworkModelWlsValueTemplate = "%s:%s:%s:%s:%d:%d"       // clusterKey, kind, namespace, name, port, stream_direction
	BehavioralLearnGlobalConfigMapName          = "bl-global-config"
	BehavioralLearnGlobalConfigMapValueTemplate = "%t:%d:%t:%t" // ignore_known_attack, learn_time, show_unrelated_res,auto_learn_new_res
)

type BehavioralLearnTaskItem struct {
	ResourceUUID uint32 `json:"resource_uuid"`
	Cluster      string `json:"cluster"`
	Namespace    string `json:"namespace"`
	Kind         string `json:"kind"`
	Name         string `json:"name"`
	StartTime    int64  `json:"start_time"`
	LearnTime    int64  `json:"learn_time"`
}

const (
	BehavioralLearnKafkaFileEvent    = 1
	BehavioralLearnKafkaCommandEvent = 2
	BehavioralLearnKafkaNetworkEvent = 3
	BehavioralLearnStatusChangeEvent = 4

	BehavioralLearnKafkaFileEventStr    = "file"
	BehavioralLearnKafkaCommandEventStr = "command"
	BehavioralLearnKafkaNetworkEventStr = "network"
	BehavioralLearnStatusChangeEventStr = "status_change"

	// 0: not start, 1: running, 2: ready, 3: enabled
	BehavioralLearningStatusNotStart = 0
	BehavioralLearningStatusRunning  = 1
	BehavioralLearningStatusReady    = 2
	BehavioralLearningStatusEnabled  = 3
)

type BehavioralKafkaEvent struct {
	ResourceUUID    uint32 `json:"resource_uuid"`
	ContainerID     string `json:"container_id"`
	ContainerName   string `json:"container_name"`
	EventType       int    `json:"event_type"` // 1: file, 2: command, 3: network
	Name            string `json:"name"`
	User            string `json:"user"`
	Path            string `json:"path"`
	FilePath        string `json:"file_path"`
	Permission      int    `json:"permission"`
	Command         string `json:"command"`
	Port            int    `json:"port"`
	StreamDirection int    `json:"stream_direction"`
	ProcessName     string `json:"process_name"`
	LearningStatus  int    `json:"learning_status"`
	SourceResource  string `json:"source_resource"`
	DestResource    string `json:"dest_resource"`
	ClusterKey      string `json:"cluster_key"`
	Namespace       string `json:"namespace"`
	Kind            string `json:"kind"`
	ResourceName    string `json:"resource_name"`
	SonyFlakeID     uint64 `json:"id"`
	CreatedAt       int64  `json:"created_at"`
}

type BehavioralLearnFileModel struct {
	ResourceUUID  uint32 `gorm:"column:resource_uuid" json:"resource_id"`
	Id            uint64 `gorm:"column:id" json:"id"`
	Name          string `gorm:"column:name" json:"name"`
	Path          string `gorm:"column:path" json:"file_path"`
	Permission    int    `gorm:"column:permission" json:"permission"`
	UpdatedAt     int64  `gorm:"column:updated_at;autoUpdateTime" json:"updated_at"`
	IsInModel     bool   `gorm:"column:is_in_model" json:"is_in_model"`
	ContainerID   string `gorm:"column:container_id" json:"container_id"`
	ContainerName string `gorm:"column:container_name" json:"container_name"`
}

func (BehavioralLearnFileModel) TableName() string {
	return "behavioral_learn_file_model"
}

type BehavioralLearnCommandModel struct {
	ResourceUUID  uint32 `gorm:"column:resource_uuid" json:"resource_id"`
	Id            uint64 `gorm:"column:id" json:"id"`
	Command       string `gorm:"column:command" json:"command"`
	UpdatedAt     int64  `gorm:"column:updated_at;autoUpdateTime" json:"updated_at"`
	User          string `gorm:"column:user" json:"user"`
	Path          string `gorm:"column:path" json:"path"`
	IsInModel     bool   `gorm:"column:is_in_model" json:"is_in_model"`
	ContainerID   string `gorm:"column:container_id" json:"container_id"`
	ContainerName string `gorm:"column:container_name" json:"container_name"`
}

func (BehavioralLearnCommandModel) TableName() string {
	return "behavioral_learn_command_model"
}

type BehavioralLearnNetworkModel struct {
	ResourceUUID       uint32 `gorm:"column:resource_uuid" json:"resource_id"`
	Id                 uint64 `gorm:"column:id" json:"id"`
	Port               int    `gorm:"column:port" json:"port"`
	UpdatedAt          int64  `gorm:"column:updated_at; autoUpdateTime" json:"updated_at"`
	SourceResource     string `gorm:"column:source_resource" json:"source_resource"`
	DestResource       string `gorm:"column:dest_resource" json:"dest_resource"`
	StreamDirection    int    `gorm:"column:stream_direction" json:"stream_direction"`
	ObjectResourceUUID uint32 `gorm:"column:object_resource_uuid" json:"object_resource_uuid"`
	ProcessName        string `gorm:"column:process_name" json:"process_name"`
	IsInModel          bool   `gorm:"column:is_in_model" json:"is_in_model"`
	ContainerID        string `gorm:"column:container_id" json:"container_id"`
	ClusterKey         string `gorm:"column:cluster_key" json:"cluster_key"`
	ResourceNamespace  string `gorm:"column:resource_namespace" json:"resource_namespace"`
	ResourceKind       string `gorm:"column:resource_kind" json:"resource_kind"`
	ResourceName       string `gorm:"column:resource_name" json:"resource_name"`
	ContainerName      string `gorm:"column:container_name" json:"container_name"`
}

func (BehavioralLearnNetworkModel) TableName() string {
	return "behavioral_learn_network_model"
}

type BehavioralLearnModelOperationLog struct {
	ResourceUUID uint32 `gorm:"column:resource_uuid" json:"resource_id"`
	User         string `gorm:"column:user" json:"user"`
	Action       string `gorm:"column:action" json:"action"`
	CreatedAt    int64  `gorm:"column:created_at; autoCreateTime:milli" json:"created_at"`
	ID           uint64 `gorm:"column: id; column:id" json:"id"`
	ModelType    string `gorm:"column:model_type" json:"model_type"`
}

func (BehavioralLearnModelOperationLog) TableName() string {
	return "behavioral_learn_model_operation_log"
}

type BehavioralLearnGlobalConfig struct {
	IgnoreKnownAttack bool  `gorm:"column:ignore_known_attack" json:"ignore_known_attack,omitempty"`
	LearnTime         int   `gorm:"column:learn_time" json:"learn_time,omitempty"`
	ShowUnrelatedRes  bool  `gorm:"column:show_unrelated_res" json:"show_unrelated_res,omitempty"`
	AutoLearnNewRes   bool  `gorm:"column:auto_learn_new_res" json:"auto_learn_new_res,omitempty"`
	UpdatedAt         int64 `gorm:"column:updated_at; autoUpdateTime" json:"updated_at,omitempty"`
}

func (BehavioralLearnGlobalConfig) TableName() string {
	return "behavioral_learn_global_config"
}

type BehavioralLearnFileModelGlobalWhiteList struct {
	ID         int64  `gorm:"column:id" json:"id"`
	Name       string `gorm:"column:name" json:"name"`
	Path       string `gorm:"column:path" json:"path"`
	Permission int    `gorm:"column:permission" json:"permission"`
	UpdatedAt  int64  `gorm:"column:updated_at; autoUpdateTime" json:"updated_at"`
	CreatedAt  int64  `gorm:"column:created_at; autoCreateTime:milli" json:"created_at"`
}

func (BehavioralLearnFileModelGlobalWhiteList) TableName() string {
	return "behavioral_learn_file_model_global_white_list"
}

type BehavioralLearnCommandModelGlobalWhiteList struct {
	ID        int64  `gorm:"column:id" json:"id"`
	Command   string `gorm:"column:command" json:"command"`
	User      string `gorm:"column:user" json:"user"`
	Path      string `gorm:"column:path" json:"path"`
	UpdatedAt int64  `gorm:"column:updated_at; autoUpdateTime" json:"updated_at"`
	CreatedAt int64  `gorm:"column:created_at; autoCreateTime:milli" json:"created_at"`
}

func (BehavioralLearnCommandModelGlobalWhiteList) TableName() string {
	return "behavioral_learn_command_model_global_white_list"
}

type BehavioralLearnNetworkModelGlobalWhiteList struct {
	ID                 int64  `gorm:"column:id" json:"id"`
	Port               int    `gorm:"column:port" json:"port"`
	ObjectResourceUUID uint32 `gorm:"column:object_resource_uuid" json:"object_resource_uuid"`
	StreamDirection    int    `gorm:"column:stream_direction" json:"stream_direction"`
	ClusterKey         string `gorm:"column:cluster_key" json:"cluster_key"`
	Kind               string `gorm:"column:kind" json:"kind"`
	Name               string `gorm:"column:name" json:"name"`
	Namespace          string `gorm:"column:namespace" json:"namespace"`
	UpdatedAt          int64  `gorm:"column:updated_at; autoUpdateTime" json:"updated_at"`
	CreatedAt          int64  `gorm:"column:created_at; autoCreateTime:milli" json:"created_at"`
}

func (BehavioralLearnNetworkModelGlobalWhiteList) TableName() string {
	return "behavioral_learn_network_model_global_white_list"
}

type BehavioralLearnModelConfig struct {
	ResourceUUID uint32 `json:"resource_id"`
	Enabled      bool   `json:"enabled"`
}

type BehavioralLearnStatusMix struct {
	ResourceUUID             uint32   `gorm:"resource_id"`
	BehavioralLearnStatus    int8     `json:"behavioral_learn_status"` // 0: not start, 1: running, 2: ready, 3: enabled
	BehavioralLearnStartTime int64    `json:"behavioral_learn_start_time"`
	ClusterKey               string   `json:"cluster_key"`
	Namespace                string   `json:"namespace"`
	Kind                     string   `gorm:"kind"`
	Name                     string   `gorm:"name"`
	NotInModelCount          int64    `gorm:"not_in_model_count"`
	Images                   []string `json:"images"`
	IsCanLearn               bool     `json:"is_can_learn"`
}
