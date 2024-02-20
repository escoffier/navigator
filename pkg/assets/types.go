package assets

import (
	// don't replace it; need the order of fields for marshal
	"encoding/json"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	netv1 "k8s.io/api/networking/v1"
	"strconv"
	"strings"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
	defensev1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/defense/v1"
)

type ResourceKind string

const (
	KindReplicaSet            ResourceKind = "ReplicaSet"
	KindDaemonSet             ResourceKind = "DaemonSet"
	KindStatefulSet           ResourceKind = "StatefulSet"
	KindReplicationController ResourceKind = "ReplicationController"
	KindDeployment            ResourceKind = "Deployment"
	KindJob                   ResourceKind = "Job"
	KindCronJob               ResourceKind = "CronJob"
	KindPodNoOwner            ResourceKind = "Pod"
)

var ResourceKindApiVersion = map[ResourceKind]string{
	KindDeployment:            "apps/v1",
	KindDaemonSet:             "apps/v1",
	KindReplicaSet:            "apps/v1",
	KindStatefulSet:           "apps/v1",
	KindJob:                   "batch/v1",
	KindCronJob:               "batch/v1beta1",
	KindReplicationController: "v1",
	KindPodNoOwner:            "v1",
}

// const (
//
//	Running = iota
//	Created
//	Restarting
//	Removing
//	Paused
//	Exited
//	Dead
//	All
//
// )
const (
	Running = iota
	Created
	Exited
	Unknown
	All
)
const ActiveCRIState = 2 //  有效的状态阈值 : status <2

const ( // 服务名称
	BusiSvcTomcat   = "Tomcat"
	BusiSvcAppache  = "Apache"
	BusiSvcNginx    = "Nginx"
	BusiSvcWeblogic = "Weblogic"
	BusiSvcWildfly  = "Wildfly"
	//BusiSvcJboss      = "Jboss"
	BusiSvcWebSphere  = "WebSphere"
	BusiSvcOpenResty  = "OpenResty"
	BusiSvcGrafana    = "Grafana"
	BusiSvcRedis      = "Redis"
	BusiSvcMysql      = "Mysql"
	BusiSvcPostgreSQL = "PostgreSQL"
	BusiSvcMogoDB     = "MogoDB"
	BusiSvcRsyslog    = "Rsyslog"
)

const ( // 编程语言
	BusiFrameworkJava   = "Java"
	BusiFrameworkPhp    = "Php"
	BusiFrameworkPython = "Python"
	BusiFrameworkNet    = ".Net"
	BusiFrameworkRuby   = "Ruby"
	BusiFrameworkNodejs = "Node.js"
)

const ( // 服务类型
	BusiSvcTypeWeb       = "Web服务"
	BusiSvcTypeWebEn     = "Web services"
	BusiSvcTypeDb        = "数据库"
	BusiSvcTypeDbEn      = "Databases"
	BusiSvcTypeMonitor   = "监控服务"
	BusiSvcTypeMonitorEn = "monitoring services"
)

var BusiSvcTypeMap = map[string]string{
	BusiSvcTomcat:   BusiSvcTypeWebEn,
	BusiSvcAppache:  BusiSvcTypeWebEn,
	BusiSvcNginx:    BusiSvcTypeWebEn,
	BusiSvcWeblogic: BusiSvcTypeWebEn,
	BusiSvcWildfly:  BusiSvcTypeWebEn,
	//BusiSvcJboss:      BusiSvcTypeWeb,
	BusiSvcWebSphere:  BusiSvcTypeWebEn,
	BusiSvcOpenResty:  BusiSvcTypeWebEn,
	BusiSvcGrafana:    BusiSvcTypeMonitorEn,
	BusiSvcRedis:      BusiSvcTypeDbEn,
	BusiSvcMysql:      BusiSvcTypeDbEn,
	BusiSvcPostgreSQL: BusiSvcTypeDbEn,
	BusiSvcMogoDB:     BusiSvcTypeDbEn,
	BusiSvcRsyslog:    BusiSvcTypeMonitorEn,
}

func GetRawContainerStatusStr(status int) string {
	switch status {
	case Running:
		return string(kubecontainer.ContainerStateRunning)
	case Created:
		return string(kubecontainer.ContainerStateCreated)
	case Exited:
		return string(kubecontainer.ContainerStateExited)
	case Unknown:
		return string(kubecontainer.ContainerStateUnknown)
	default:
		return string(kubecontainer.ContainerStateUnknown)
	}
}

func GetRawContainerStatusInt(status kubecontainer.State) int {
	switch status {
	case kubecontainer.ContainerStateRunning:
		return Running
	case kubecontainer.ContainerStateCreated:
		return Created
	case kubecontainer.ContainerStateExited:
		return Exited
	case kubecontainer.ContainerStateUnknown:
		return Unknown
	default:
		return Unknown
	}
}

type ConvertFunc func(cluster string, wl interface{}) *TensorResource

var TensorResourceFuncs = map[ResourceKind]ConvertFunc{
	KindDeployment:            NewResourceFromDeployment,
	KindReplicaSet:            NewResourceFromReplicaSet,
	KindDaemonSet:             ResourceFromDaemonSet,
	KindStatefulSet:           NewResourceFromStatefulSet,
	KindReplicationController: NewResourceFromReplicationController,
	KindJob:                   NewResourceFromJob,
	KindCronJob:               NewResourceFromCronJob,
}

/*
TensorResource is an abstract concept: it's a general abstraction of the deployment unit in a kubernetes cluster. They are all pod controllers or the controller of the controller of pods.
It could be a ReplicaSet, DaemonSet, StatefulSet, ReplicationController, Deployment, Job. The Kind field will identify the type of it.
All fields are immutable.
*/
type TensorResource struct {
	metav1.ObjectMeta
	Cluster       string                  `json:"cluster"`
	Kind          ResourceKind            `json:"kind"`
	originRef     interface{}             `json:"origin_ref"` // the original object
	LabelSelector *metav1.LabelSelector   `json:"label_selector"`
	PodTemplate   *corev1.PodTemplateSpec `json:"pod_template"`
	CreateTime    time.Time               `json:"create_time"`
	dupChecked    bool
}

func (r *TensorResource) SetDuplicatedChecked(checked bool) {
	r.dupChecked = checked
}
func (r *TensorResource) DuplicatedChecked() bool {
	return r.dupChecked
}
func (r *TensorResource) KeyName() string {
	sb := strings.Builder{}
	sb.WriteString(r.Cluster)
	sb.WriteRune('\n')
	sb.WriteString(string(r.Kind))
	sb.WriteRune('\n')
	sb.WriteString(r.Name)
	sb.WriteRune('\n')
	sb.WriteString(r.Namespace)
	return sb.String()
}
func (r *TensorResource) IdentityString() string {
	sb := strings.Builder{}
	if r.PodTemplate != nil {
		specBytes, err := json.Marshal(r.PodTemplate.Spec)
		if err == nil {
			sb.WriteString(string(specBytes))
		}
	}
	sb.WriteRune('\n')
	if !r.CreationTimestamp.IsZero() {
		sb.WriteString(strconv.FormatInt(r.CreationTimestamp.UnixMilli(), 10))
	}
	return sb.String()
}

type PoolInfo struct {
	PoolName    string `json:"poolName"`
	PoolUID     string `json:"poolUID"`
	PoolPodName string `json:"poolPodName"`
	PoolPodUID  string `json:"poolPodUID"`
}

type TensorPod struct {
	*corev1.Pod
	Cluster    string                 `json:"cluster"`
	Owner      *metav1.OwnerReference `json:"owner"`
	PoolInfo   *PoolInfo              `json:"poolInfo"`
	dupChecked bool
}

func (r *TensorPod) DuplicatedChecked() bool {
	return r.dupChecked
}
func (r *TensorPod) SetDuplicatedChecked(checked bool) {
	r.dupChecked = checked
}
func (p *TensorPod) KeyName() string {
	sb := strings.Builder{}
	sb.WriteString(p.Cluster)
	sb.WriteRune('\n')
	sb.WriteString("Pod")
	sb.WriteRune('\n')
	sb.WriteString(p.Name)
	sb.WriteRune('\n')
	sb.WriteString(p.Namespace)
	return sb.String()
}

func getContainerStatusStr(cs []corev1.ContainerStatus) string {
	s := strings.Builder{}
	for _, c := range cs {
		s.WriteString(c.Name)
		s.WriteRune('\t')
		s.WriteString(c.ContainerID)
		s.WriteRune('\t')
		s.WriteString(c.Image)
		s.WriteRune('\t')
		s.WriteString(c.ImageID)
		s.WriteRune('\n')
		s.WriteString(c.State.String())
		s.WriteRune('\n')
		s.WriteString(fmt.Sprintf("%v", c.Ready))
	}
	return s.String()
}
func (p *TensorPod) IdentityString() string {
	sb := strings.Builder{}
	podSpecBytes, err := json.Marshal(p.Spec)
	if err == nil {
		sb.WriteString(string(podSpecBytes))
	}
	sb.WriteRune('\n')
	sb.WriteString(p.Status.PodIP)
	sb.WriteRune('\n')
	sb.WriteString(p.Status.HostIP)
	sb.WriteRune('\n')
	sb.WriteString(getContainerStatusStr(p.Status.InitContainerStatuses))
	sb.WriteRune('\n')
	sb.WriteString(getContainerStatusStr(p.Status.ContainerStatuses))
	return sb.String()
}

// ingress
type TensorIngress struct {
	Cluster string
	*netv1.Ingress
	dupChecked bool
}

func (t *TensorIngress) IdentityString() string {
	sb := strings.Builder{}
	sb.WriteString(t.ResourceVersion)
	return sb.String()
}

func (t *TensorIngress) KeyName() string {
	sb := strings.Builder{}
	sb.WriteString(t.Cluster)
	sb.WriteRune('\n')
	sb.WriteString("Ingress")
	sb.WriteRune('\n')
	sb.WriteString(t.Name)
	sb.WriteRune('\n')
	sb.WriteString(t.Namespace)
	return sb.String()
}

func (t *TensorIngress) SetDuplicatedChecked(checked bool) {
	t.dupChecked = checked
}

func (t *TensorIngress) DuplicatedChecked() bool {
	return t.dupChecked
}

// Service
type TensorService struct {
	Cluster string
	*corev1.Service
	dupChecked bool
}

func (t *TensorService) IdentityString() string {
	sb := strings.Builder{}
	sb.WriteString(t.ResourceVersion)
	return sb.String()
}

func (t *TensorService) KeyName() string {
	sb := strings.Builder{}
	sb.WriteString(t.Cluster)
	sb.WriteRune('\n')
	sb.WriteString("Service")
	sb.WriteRune('\n')
	sb.WriteString(t.Name)
	sb.WriteRune('\n')
	sb.WriteString(t.Namespace)
	return sb.String()
}

func (t *TensorService) SetDuplicatedChecked(checked bool) {
	t.dupChecked = checked
}

func (t *TensorService) DuplicatedChecked() bool {
	return t.dupChecked
}

// Endpoints
type TensorEndpoints struct {
	Cluster string
	*EndpointsTmp
	dupChecked bool
}
type EndpointsTmp struct {
	*corev1.Endpoints
	ServiceName string
}

func (t *TensorEndpoints) IdentityString() string {
	sb := strings.Builder{}
	if len(t.Subsets) > 0 {
		sb.WriteString(t.ResourceVersion)
	} else {
		sb.WriteString("0")
	}
	return sb.String()
}

func (t *TensorEndpoints) KeyName() string {
	sb := strings.Builder{}
	sb.WriteString(t.Cluster)
	sb.WriteRune('\n')
	sb.WriteString("Endpoints")
	sb.WriteRune('\n')
	sb.WriteString(t.Name)
	sb.WriteRune('\n')
	sb.WriteString(t.Namespace)
	return sb.String()
}

func (t *TensorEndpoints) SetDuplicatedChecked(checked bool) {
	t.dupChecked = checked
}

func (t *TensorEndpoints) DuplicatedChecked() bool {
	return t.dupChecked
}

func (e *EndpointsTmp) IdentityString() string {
	sb := strings.Builder{}
	if len(e.Subsets) > 0 {
		sb.WriteString(e.ResourceVersion)
	} else {
		sb.WriteString("0")
	}
	return sb.String()
}

func (e *EndpointsTmp) KeyName() string {
	sb := strings.Builder{}
	sb.WriteString("Endpoints")
	sb.WriteRune('\n')
	sb.WriteString(e.Name)
	sb.WriteRune('\n')
	sb.WriteString(e.Namespace)
	return sb.String()
}

func (e *EndpointsTmp) SetDuplicatedChecked(checked bool) {}

func (e *EndpointsTmp) DuplicatedChecked() bool {
	return false
}

// Secret
type TensorSecret struct {
	Cluster string
	*corev1.Secret
	dupChecked bool
}

func (t *TensorSecret) IdentityString() string {
	sb := strings.Builder{}
	sb.WriteString(t.ResourceVersion)
	return sb.String()
}

func (t *TensorSecret) KeyName() string {
	sb := strings.Builder{}
	sb.WriteString(t.Cluster)
	sb.WriteRune('\n')
	sb.WriteString("Secret")
	sb.WriteRune('\n')
	sb.WriteString(t.Name)
	sb.WriteRune('\n')
	sb.WriteString(t.Namespace)
	return sb.String()
}

func (t *TensorSecret) SetDuplicatedChecked(checked bool) {
	t.dupChecked = checked
}

func (t *TensorSecret) DuplicatedChecked() bool {
	return t.dupChecked
}

// PV
type TensorPV struct {
	Cluster string
	*corev1.PersistentVolume
	dupChecked bool
}

func (t *TensorPV) IdentityString() string {
	sb := strings.Builder{}
	sb.WriteString(t.ResourceVersion)
	return sb.String()
}

func (t *TensorPV) KeyName() string {
	sb := strings.Builder{}
	sb.WriteString(t.Cluster)
	sb.WriteRune('\n')
	sb.WriteString("PersistentVolume")
	sb.WriteRune('\n')
	sb.WriteString(t.Name)
	sb.WriteRune('\n')
	sb.WriteString(t.Namespace)
	return sb.String()
}

func (t *TensorPV) SetDuplicatedChecked(checked bool) {
	t.dupChecked = checked
}

func (t *TensorPV) DuplicatedChecked() bool {
	return t.dupChecked
}

// PVC
type TensorPVC struct {
	Cluster string
	*corev1.PersistentVolumeClaim
	dupChecked bool
}

func (t *TensorPVC) IdentityString() string {
	sb := strings.Builder{}
	sb.WriteString(t.ResourceVersion)
	return sb.String()
}

func (t *TensorPVC) KeyName() string {
	sb := strings.Builder{}
	sb.WriteString(t.Cluster)
	sb.WriteRune('\n')
	sb.WriteString("PersistentVolumeClaim")
	sb.WriteRune('\n')
	sb.WriteString(t.Name)
	sb.WriteRune('\n')
	sb.WriteString(t.Namespace)
	return sb.String()
}

func (t *TensorPVC) SetDuplicatedChecked(checked bool) {
	t.dupChecked = checked
}

func (t *TensorPVC) DuplicatedChecked() bool {
	return t.dupChecked
}

type TensorRole struct {
	Cluster string
	*rbacv1.Role
	dupChecked bool
}

func (r *TensorRole) DuplicatedChecked() bool {
	return r.dupChecked
}
func (r *TensorRole) SetDuplicatedChecked(checked bool) {
	r.dupChecked = checked
}
func (p *TensorRole) KeyName() string {
	sb := strings.Builder{}
	sb.WriteString(p.Cluster)
	sb.WriteRune('\n')
	sb.WriteString("Role")
	sb.WriteRune('\n')
	sb.WriteString(p.Name)
	sb.WriteRune('\n')
	sb.WriteString(p.Namespace)
	return sb.String()
}
func (p *TensorRole) IdentityString() string {
	sb := strings.Builder{}
	sb.WriteString(p.ResourceVersion)
	return sb.String()
}

type TensorClusterRole struct {
	Cluster string
	*rbacv1.ClusterRole
	dupChecked bool
}

func (r *TensorClusterRole) DuplicatedChecked() bool {
	return r.dupChecked
}
func (r *TensorClusterRole) SetDuplicatedChecked(checked bool) {
	r.dupChecked = checked
}

func (p *TensorClusterRole) KeyName() string {
	sb := strings.Builder{}
	sb.WriteString(p.Cluster)
	sb.WriteRune('\n')
	sb.WriteString("ClusterRole")
	sb.WriteRune('\n')
	sb.WriteString(p.Name)
	sb.WriteRune('\n')
	sb.WriteString(p.Namespace)
	return sb.String()
}
func (p *TensorClusterRole) IdentityString() string {
	sb := strings.Builder{}
	sb.WriteString(p.ResourceVersion)
	return sb.String()
}

type TensorNamespace struct {
	Cluster string
	*corev1.Namespace
	dupChecked bool
}

func (r *TensorNamespace) DuplicatedChecked() bool {
	return r.dupChecked
}
func (r *TensorNamespace) SetDuplicatedChecked(c bool) {
	r.dupChecked = c
}
func (p *TensorNamespace) KeyName() string {
	sb := strings.Builder{}
	sb.WriteString(p.Cluster)
	sb.WriteRune('\n')
	sb.WriteString("Namespace")
	sb.WriteRune('\n')
	sb.WriteString(p.Name)
	return sb.String()
}
func (p *TensorNamespace) IdentityString() string {
	sb := strings.Builder{}
	sb.WriteString(p.ResourceVersion)
	return sb.String()
}

type TensorNode struct {
	Cluster string
	*corev1.Node
	dupChecked bool
}

func (r *TensorNode) DuplicatedChecked() bool {
	return r.dupChecked
}
func (p *TensorNode) KeyName() string {
	sb := strings.Builder{}
	sb.WriteString(p.Cluster)
	sb.WriteRune('\n')
	sb.WriteString("Node")
	sb.WriteRune('\n')
	sb.WriteString(p.Name)
	return sb.String()
}

func (r *TensorNode) SetDuplicatedChecked(checked bool) {
	r.dupChecked = checked
}

func (p *TensorNode) TailorSelf() {
	p.Spec = corev1.NodeSpec{}
	p.Status = corev1.NodeStatus{
		Phase:      p.Status.Phase,
		Addresses:  p.Status.Addresses,
		NodeInfo:   p.Status.NodeInfo,
		Conditions: p.Status.Conditions,
	}
}
func (p *TensorNode) IdentityString() string {
	sb := strings.Builder{}
	// specBytes, err := json.Marshal(p.Spec)
	// if err == nil {
	// 	sb.WriteString(string(specBytes))
	// }
	// sb.WriteRune('\n')
	sb.WriteString(string(p.Status.Phase))
	sb.WriteRune('\n')
	condBytes, err := json.Marshal(p.Status.Conditions)
	if err == nil {
		sb.WriteString(string(condBytes))
	}
	sb.WriteRune('\n')

	addrBytes, err := json.Marshal(p.Status.Addresses)
	if err == nil {
		sb.WriteString(string(addrBytes))
	}
	sb.WriteRune('\n')
	ninfo, err := json.Marshal(p.Status.NodeInfo)
	if err == nil {
		sb.WriteString(string(ninfo))
	}
	sb.WriteRune('\n')
	if !p.CreationTimestamp.IsZero() {
		sb.WriteString(strconv.FormatInt(p.CreationTimestamp.UnixMilli(), 10))
	}

	return sb.String()
}

type TensorHoneySpot struct {
	Cluster string
	*defensev1.Honeypot
	dupChecked bool
}

func (r *TensorHoneySpot) DuplicatedChecked() bool {
	return r.dupChecked
}
func (r *TensorHoneySpot) SetDuplicatedChecked(checked bool) {
	r.dupChecked = checked
}

func (r *TensorHoneySpot) KeyName() string {
	sb := strings.Builder{}
	sb.WriteString(r.Cluster)
	sb.WriteRune('\n')
	sb.WriteString(string(r.Kind))
	sb.WriteRune('\n')
	sb.WriteString(r.Name)
	sb.WriteRune('\n')
	sb.WriteString(r.Namespace)
	return sb.String()
}
func (r *TensorHoneySpot) IdentityString() string {
	sb := strings.Builder{}
	sb.WriteString(r.ResourceVersion)
	return sb.String()
}

// type TensorRawContainer model.TensorRawContainer
type TensorRawContainer struct {
	*model.TensorRawContainer
	Discovery *TensorRawContainerDiscovery `json:"discovery,omitempty"`
}

type TensorRawContainerDiscovery struct {
	Frameworks []*ContainerFrameworkInfo
	Services   []*ContainerSvcInfo
}

type ContainerSvcInfo struct {
	Name      string // 服务类型
	Version   string
	Cmd       string
	Port      string
	RootDir   string // 主目录路径
	BinaryDir string
	ConfigDir string
	DataDir   string
	LogDir    string
}

type ContainerFrameworkInfo struct {
	LanguageName     string
	LanguageVersion  string
	FrameworkName    string
	FrameworkVersion string
	LanguageBinPath  string
	FrameworkPath    string
}

type TensorSync struct {
	Cluster  string
	NodeName string
	SyncTime time.Time
}

func NewResourceFromPodNoOwnerOrStaticPod(cluster string, pod *corev1.Pod) *TensorResource {
	if pod == nil {
		return nil
	}
	res := TensorResource{
		ObjectMeta:    *pod.ObjectMeta.DeepCopy(),
		Kind:          KindPodNoOwner,
		Cluster:       cluster,
		originRef:     pod,
		LabelSelector: nil,
		// OwnerReferences: pod.OwnerReferences,
		// Labels:          pod.Labels,
		PodTemplate: &corev1.PodTemplateSpec{Spec: pod.Spec},
		CreateTime:  pod.CreationTimestamp.Time,
	}
	return &res
}
func NewResourceFromReplicationController(cluster string, wl interface{}) *TensorResource {
	rs := wl.(*corev1.ReplicationController)
	if rs == nil {
		return nil
	}
	res := TensorResource{
		ObjectMeta: *rs.ObjectMeta.DeepCopy(),
		Kind:       KindReplicationController,
		Cluster:    cluster,
		// UID:           string(rs.UID),
		originRef:     rs,
		LabelSelector: &metav1.LabelSelector{MatchLabels: rs.Spec.Selector},
		// OwnerReferences: rs.OwnerReferences,
		// Labels:          rs.Labels,
		PodTemplate: rs.Spec.Template,
		CreateTime:  rs.CreationTimestamp.Time,
	}
	return &res
}

func NewResourceFromReplicaSet(cluster string, wl interface{}) *TensorResource {
	rs, ok := wl.(*appsv1.ReplicaSet)
	if !ok {
		return nil
	}
	if rs == nil {
		return nil
	}
	res := TensorResource{
		ObjectMeta: *rs.ObjectMeta.DeepCopy(),
		Kind:       KindReplicaSet,
		Cluster:    cluster,
		// Namespace:       rs.Namespace,
		// Name:            rs.Name,
		// UID:           string(rs.UID),
		originRef:     rs,
		LabelSelector: rs.Spec.Selector,
		// OwnerReferences: rs.OwnerReferences,
		// Labels:          rs.Labels,
		PodTemplate: &rs.Spec.Template,
		CreateTime:  rs.CreationTimestamp.Time,
	}
	return &res
}

func NewResourceFromStatefulSet(cluster string, obj interface{}) *TensorResource {
	ss, ok := obj.(*appsv1.StatefulSet)
	if !ok {
		return nil
	}
	if ss == nil {
		return nil
	}
	res := TensorResource{
		ObjectMeta: *ss.ObjectMeta.DeepCopy(),
		Kind:       KindStatefulSet,
		Cluster:    cluster,
		// Namespace:       ss.Namespace,
		// Name:            ss.Name,
		// UID:           string(ss.UID),
		originRef:     ss,
		LabelSelector: ss.Spec.Selector,
		// OwnerReferences: ss.OwnerReferences,
		// Labels:          ss.Labels,
		PodTemplate: &ss.Spec.Template,
		CreateTime:  ss.CreationTimestamp.Time,
	}
	return &res
}

func ResourceFromDaemonSet(cluster string, wl interface{}) *TensorResource {
	ds := wl.(*appsv1.DaemonSet)
	return NewResourceFromDaemonSet(cluster, ds)
}

func NewResourceFromDaemonSet(cluster string, ss *appsv1.DaemonSet) *TensorResource {
	if ss == nil {
		return nil
	}
	res := TensorResource{
		ObjectMeta: *ss.ObjectMeta.DeepCopy(),
		Kind:       KindDaemonSet,
		Cluster:    cluster,
		// Namespace:       ss.Namespace,
		// Name:            ss.Name,
		// UID:           string(ss.UID),
		originRef:     ss,
		LabelSelector: ss.Spec.Selector,
		// OwnerReferences: ss.OwnerReferences,
		// Labels:          ss.Labels,
		PodTemplate: &ss.Spec.Template,
		CreateTime:  ss.CreationTimestamp.Time,
	}
	return &res
}

func NewResourceFromDeployment(cluster string, wl interface{}) *TensorResource {
	ss, ok := wl.(*appsv1.Deployment)
	if !ok {
		logging.Get().Error().Msg("not deployment")
		return nil
	}
	if ss == nil {
		return nil
	}
	res := TensorResource{
		ObjectMeta: *ss.ObjectMeta.DeepCopy(),
		Kind:       KindDeployment,
		Cluster:    cluster,
		// UID:           string(ss.UID),
		originRef:     ss,
		LabelSelector: ss.Spec.Selector,
		// OwnerReferences: ss.OwnerReferences,
		// Labels:          ss.Labels,
		PodTemplate: &ss.Spec.Template,
		CreateTime:  ss.CreationTimestamp.Time,
	}
	return &res
}
func NewResourceFromCronJob(cluster string, wl interface{}) *TensorResource {
	ss, ok := wl.(*batchv1beta.CronJob)
	if !ok {
		ssv1, ok := wl.(*batchv1.CronJob)
		if !ok {
			return nil
		}
		return &TensorResource{
			ObjectMeta:    *ssv1.ObjectMeta.DeepCopy(),
			Kind:          KindCronJob,
			Cluster:       cluster,
			originRef:     ssv1,
			LabelSelector: ssv1.Spec.JobTemplate.Spec.Selector,
			PodTemplate:   &ssv1.Spec.JobTemplate.Spec.Template,
			CreateTime:    ssv1.CreationTimestamp.Time,
		}
	}
	if ss == nil {
		return nil
	}
	return &TensorResource{
		ObjectMeta:    *ss.ObjectMeta.DeepCopy(),
		Kind:          KindCronJob,
		Cluster:       cluster,
		originRef:     ss,
		LabelSelector: ss.Spec.JobTemplate.Spec.Selector,
		PodTemplate:   &ss.Spec.JobTemplate.Spec.Template,
		CreateTime:    ss.CreationTimestamp.Time,
	}
}

func NewResourceFromJob(cluster string, wl interface{}) *TensorResource {
	ss, ok := wl.(*batchv1.Job)
	if !ok {
		return nil
	}
	if ss == nil {
		return nil
	}
	res := TensorResource{
		ObjectMeta: *ss.ObjectMeta.DeepCopy(),
		Kind:       KindJob,
		Cluster:    cluster,
		// Namespace:       ss.Namespace,
		// Name:            ss.Name,
		// UID:           string(ss.UID),
		originRef:     ss,
		LabelSelector: ss.Spec.Selector,
		// OwnerReferences: ss.OwnerReferences,
		// Labels:          ss.Labels,
		PodTemplate: &ss.Spec.Template,
		CreateTime:  ss.CreationTimestamp.Time,
	}
	return &res
}

func (r *TensorResource) GetReplicaSet() (*appsv1.ReplicaSet, bool) {
	rs, ok := r.originRef.(*appsv1.ReplicaSet)
	return rs, ok
}

func (r *TensorResource) GetDaemonSet() (*appsv1.DaemonSet, bool) {
	rs, ok := r.originRef.(*appsv1.DaemonSet)
	return rs, ok
}

func (r *TensorResource) GetStatefulSet() (*appsv1.StatefulSet, bool) {
	rs, ok := r.originRef.(*appsv1.StatefulSet)
	return rs, ok
}

func (r *TensorResource) GetDeployment() (*appsv1.Deployment, bool) {
	rs, ok := r.originRef.(*appsv1.Deployment)
	return rs, ok
}

func (r *TensorResource) GetJob() (*batchv1.Job, bool) {
	rs, ok := r.originRef.(*batchv1.Job)
	return rs, ok
}

func (r *TensorResource) GetCronJob() (*batchv1beta.CronJob, bool) {
	rs, ok := r.originRef.(*batchv1beta.CronJob)
	return rs, ok
}

func (r *TensorResource) GetPod() (*corev1.Pod, bool) {
	rs, ok := r.originRef.(*corev1.Pod)
	return rs, ok
}

func (r *TensorResource) GetReplicationController() (*corev1.ReplicationController, bool) {
	rs, ok := r.originRef.(*corev1.ReplicationController)
	return rs, ok
}
