package association

import (
	"errors"
	"strings"
	"time"

	"github.com/falcosecurity/client-go/pkg/api/outputs"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
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

type Link struct {
	SrcLoc      TargetLocation
	SrcAggrKey  string
	DestLoc     TargetLocation
	DestAggrKey string
}

type AssociationEvent interface {
	GetID() uint64
	GetEvents() []PodContainerEvent
	GetEventsNum() int
	GetNodesNum() int
	GetAssociatedLinks() []Link
	SetID(evtID uint64)
	PostActionSetting(evtID uint64, submitOK bool)
}

type Aggragator interface {
	AddEvent(e *outputs.Response) error
	Outputs() <-chan AssociationEvent
}

type PodContainerLoc struct {
	ckey       string
	locIndexes []string
	str        string
}

func (pcl PodContainerLoc) ClusterKey() string {
	return pcl.ckey
}
func (pcl PodContainerLoc) Type() LocType { return LocType_PodContainer }
func (pcl PodContainerLoc) GetLocationElem(elemIdx int) (string, bool) {
	if elemIdx >= len(pcl.locIndexes) || elemIdx < 0 {
		return "", false
	}
	return pcl.locIndexes[elemIdx], true
}
func (pcl PodContainerLoc) String() string {
	return pcl.str
}

type PodContainerEvent struct {
	OriginID string
	loc      *PodContainerLoc
	aggrKey  string
	module   string
	category string
	pid      string
	ppid     string
	pname    string
	ppname   string
	rule     string
	time     time.Time
}

func NewOriginEventFrom(category string, resp *outputs.Response) PodContainerEvent {
	e := PodContainerEvent{}
	e.OriginID = resp.OutputFields[rtdetect.KeyUuid]
	e.loc, _ = getLocation(resp)
	e.module = "ContainerSecurity"
	e.category = category
	pid, _ := getPid(resp)
	e.pid = pid
	pname, _ := getPName(resp)
	e.pname = pname
	ppid, _ := getParentPid(resp)
	e.ppid = ppid
	ppname, _ := getParentPName(resp)
	e.ppname = ppname
	e.time = resp.Time.AsTime()
	e.rule = resp.Rule

	return e
}
func (pce *PodContainerEvent) GetRule() string {
	return pce.rule
}

func (pce *PodContainerEvent) Module() string { return pce.module }

func (pce *PodContainerEvent) Category() string { return pce.category }

func (pce *PodContainerEvent) ID() string {
	return pce.OriginID
}
func (pce *PodContainerEvent) Location() (TargetLocation, bool) {
	return pce.loc, pce.loc != nil
}
func getLocation(resp *outputs.Response) (*PodContainerLoc, bool) {

	namespace, ok := resp.OutputFields[rtdetect.FieldK8sNsName]
	if !ok {
		return nil, false
	}
	podName, ok := resp.OutputFields[rtdetect.FieldK8sPodName]
	if !ok {
		return nil, false
	}
	clusterKey, ok := resp.OutputFields[rtdetect.KeyClusterKey]
	if !ok {
		return nil, false
	}
	containerID, ok := resp.OutputFields[rtdetect.FieldContainerId]
	if !ok {
		return nil, false
	}
	loc := PodContainerLoc{
		ckey:       clusterKey,
		locIndexes: []string{namespace, podName, containerID},
	}
	sb := strings.Builder{}
	sb.WriteString(clusterKey)
	sb.WriteRune('/')
	for i, l := range loc.locIndexes {
		sb.WriteString(l)
		if i < len(loc.locIndexes)-1 {
			sb.WriteRune('/')
		}
	}
	loc.str = sb.String()
	return &loc, true
}

func (pce *PodContainerEvent) Time() time.Time {
	return pce.time
}
func (pce *PodContainerEvent) AggregationKey() string {
	return pce.aggrKey
}
func (pce *PodContainerEvent) SetAggregationKey(assKey string) {
	pce.aggrKey = assKey
}

func (pce *PodContainerEvent) Pid() (string, bool) {
	return pce.pid, len(pce.pid) > 0
}
func (pce *PodContainerEvent) ProcessName() (string, bool) {
	return pce.pname, len(pce.pname) > 0
}
func (pce *PodContainerEvent) ParentPid() (string, bool) {
	return pce.ppid, len(pce.ppid) > 0
}
func (pce *PodContainerEvent) ParentProcessName() (string, bool) {
	return pce.ppname, len(pce.ppname) > 0
}
func getParentPid(resp *outputs.Response) (string, bool) {
	ppid, exist := resp.OutputFields[rtdetect.FieldParentProcessPid]
	if !exist || len(ppid) == 0 {
		var err error
		ppid, err = model.GetInfoFromOutput("proc_ppid=", resp.Output)
		if err != nil {
			return "", false
		}
		return ppid, true
	}
	return ppid, exist
}

func getParentPName(resp *outputs.Response) (string, bool) {
	ppname, exist := resp.OutputFields[rtdetect.FieldParentProcessName]
	if !exist || len(ppname) == 0 {
		procPname, err := model.GetInfoFromOutput("proc_pname=", resp.Output)
		if err != nil {
			return "", false
		}
		return procPname, true
	}
	return ppname, exist
}
func getPid(resp *outputs.Response) (string, bool) {
	pid, ok := resp.OutputFields[rtdetect.FieldProcessPid]
	if !ok || len(pid) == 0 {
		var err error
		pid, err = model.GetInfoFromOutput("proc_pid=", resp.Output)
		if err != nil {
			return pid, false
		}
		return pid, true
	}
	return pid, ok

}
func getPName(resp *outputs.Response) (string, bool) {
	pname, exist := resp.OutputFields[rtdetect.FieldProcessName]
	if !exist || len(pname) == 0 {
		command, exist := resp.OutputFields[rtdetect.FieldCmdline]
		if !exist || len(command) == 0 {
			pname, err := model.GetInfoFromOutput("proc_cmdline=", resp.Output)
			if err != nil || pname == "" {
				return "", false
			}
			pname = strings.TrimSpace(pname)
			return pname, true
		}

		pos := strings.IndexRune(command, ' ')
		if pos > 0 {
			return command[0:pos], true
		}
		return "", false
	}
	return pname, exist
}

type AssociationConfiguration struct {
	WindowDivisionLatency time.Duration // The latency that the aggregator will wait for submitting.
	BuildInterval         time.Duration
	MaxEventsNum          int
}
