package association

import (
	"errors"
	"strings"
	"time"

	"github.com/falcosecurity/client-go/pkg/api/outputs"
	"github.com/falcosecurity/client-go/pkg/api/schema"
	"gitlab.com/piccolo_su/vegeta/pkg/rtdetect"
)

var (
	ErrPanic     = errors.New("panic")
	ErrTimeout   = errors.New("send timeout")
	ErrIsStopped = errors.New("the aggregator is stopped")
)

type LocType string

const (
	LocType_PodContainer LocType = "pod_container" // namespace/pod_name/container_id
)

type TargetLocation interface {
	ClusterKey() string
	Type() LocType
	GetLocationElem(elemIdx int) (string, bool)
	String() string
}

type OriginEvent interface {
	ID() string
	Module() string
	Category() string
	Location() (TargetLocation, bool)
	GetRule() string
	GetPriority() schema.Priority
	Get(key string) (value string, exist bool)
	Time() time.Time
	AggregationKey() string
	SetAggregationKey(assKey string)
}
type Link struct {
	SrcLoc      TargetLocation
	SrcAggrKey  string
	DestLoc     TargetLocation
	DestAggrKey string
}

type AssociationEvent interface {
	GetID() int64
	GetEvents() []OriginEvent
	GetAssociatedLinks() []Link
	SetID(id int64)
}

type Aggragator interface {
	AddEvent(e *outputs.Response) error
	Outputs() <-chan AssociationEvent
}

type PodContainerLoc struct {
	ckey       string   `json:"cluster_key"`
	locIndexes []string `json:"loc_indexes"` // 0: namespace 1: podName 2: containerID
}

func (pcl *PodContainerLoc) ClusterKey() string {
	return pcl.ckey
}
func (pcl *PodContainerLoc) Type() LocType { return LocType_PodContainer }
func (pcl *PodContainerLoc) GetLocationElem(elemIdx int) (string, bool) {
	if elemIdx > 2 || elemIdx < 0 {
		return "", false
	}
	return pcl.locIndexes[elemIdx], true
}
func (pcl *PodContainerLoc) String() string {
	bui := strings.Builder{}
	bui.WriteString(pcl.ckey)
	bui.WriteByte('-')
	for i, e := range pcl.locIndexes {
		bui.WriteString(e)
		if i < len(pcl.locIndexes)-1 {
			bui.WriteByte('-')
		}
	}
	return bui.String()
}

type PodContainerEvent struct {
	*outputs.Response
	OriginID    string           `json:"origin_id"`
	Loc         *PodContainerLoc `json:"location"`
	aggrKey     string
	assoEventID uint64
	module      string
	category    string
}

func (pce *PodContainerEvent) Module() string { return pce.module }

func (pce *PodContainerEvent) Category() string { return pce.category }

func (pce *PodContainerEvent) ID() string {
	return pce.OriginID
}
func (pce *PodContainerEvent) Location() (TargetLocation, bool) {
	if pce.Loc != nil {
		return pce.Loc, pce.Loc != nil
	}

	namespace, ok := pce.Response.OutputFields[rtdetect.FieldK8sNsName]
	if !ok {
		return nil, false
	}
	podName, ok := pce.Response.OutputFields[rtdetect.FieldK8sPodName]
	if !ok {
		return nil, false
	}
	clusterKey, ok := pce.Response.OutputFields[rtdetect.KeyClusterKey]
	if !ok {
		return nil, false
	}
	containerID, ok := pce.Response.OutputFields[rtdetect.FieldContainerId]
	if !ok {
		return nil, false
	}
	pce.Loc = &PodContainerLoc{
		ckey:       clusterKey,
		locIndexes: []string{namespace, podName, containerID},
	}
	return pce.Loc, true
}

func (pce *PodContainerEvent) Get(key string) (value string, exist bool) {
	value, exist = pce.Response.OutputFields[key]
	return value, exist
}

func (pce *PodContainerEvent) SetAssociationEventID(id uint64) {
	pce.assoEventID = id
}

func (pce *PodContainerEvent) GetAssociationEventID() uint64 {
	return pce.assoEventID
}

func (pce *PodContainerEvent) Time() time.Time {
	return pce.Response.GetTime().AsTime()
}
func (pce *PodContainerEvent) AggregationKey() string {
	return pce.aggrKey
}
func (pce *PodContainerEvent) SetAggregationKey(assKey string) {
	pce.aggrKey = assKey
}

func (pce *PodContainerEvent) GetParentPid() (string, bool) {
	return pce.Get(rtdetect.FieldParentProcessPid)
}
func (pce *PodContainerEvent) GetParentPName() (string, bool) {
	return pce.Get(rtdetect.FieldParentProcessName)
}
func (pce *PodContainerEvent) GetPid() (string, bool) {
	return pce.Get(rtdetect.FieldProcessPid)
}
func (pce *PodContainerEvent) GetPName() (string, bool) {
	return pce.Get(rtdetect.FieldProcessName)
}

type AssociationConfiguration struct {
	SubmitLatency time.Duration // The latency that the aggregator will wait for submitting.
	BuildInterval time.Duration
	MaxEventsNum  int
}
