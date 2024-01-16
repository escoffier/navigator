package dal

import (
	"context"
	"errors"
	"fmt"
	"github.com/shopspring/decimal"
	pkgasserts "gitlab.com/piccolo_su/vegeta/pkg/assets"
	"gitlab.com/piccolo_su/vegeta/pkg/env"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/logging"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"strings"
	"time"
)

var (
	//onDupUpdatedForOnlyUpdateAt                 = []string{"updated_at"}
	onDupUpdatedForContainerClusterMangerStatus = []string{
		"status",
		"container_status",
	}
	onDupUpdatedForContainerStatus                = append(onDupUpdatedForContainerClusterMangerStatus, "updated_at")
	onDupUpdatedForContainerClusterManagerMetrics = []string{
		"version",
		"metrics_last_time",
		"cpu_usage_last",
		"cpu_usage_current",
		"cpu_system_usage_last",
		"cpu_system_usage_current",
		"online_cpus",
		"cpu_limit",
		"mem_last",
		"mem_current",
		"mem_limit",
		"block_i_last",
		"block_o_last",
		"block_i_current",
		"block_o_current",
		"time_gap",
	}
	onDupUpdatedForContainerMetrics = append(onDupUpdatedForContainerClusterManagerMetrics, "updated_at")
)

const (
	AppLabel_holmes         = "holmes"
	AppLabel_clusterManager = "cluster-manager"
	AppLabel_scanner        = "scanner"

	ContainerStatus_normal       = "Normal"
	ContainerStatus_abnormal     = "Abnormal"
	ContainerStatus_normal_int   = 0
	ContainerStatus_abnormal_int = 1
)

// 仅支持单个pod范围的容器状态入库
func UpsertContainerStatus(ctx context.Context, rdb *gorm.DB, dbIsTx bool, containers []*model.TensorsecContainerMonitor, isHolmes bool, isHealth bool) error {
	if len(containers) == 0 {
		return nil
	}
	dbFunc := func(tx *gorm.DB) error {
		var err error
		if containers[0].AppLabel == AppLabel_clusterManager {
			err = tx.Model(&model.TensorsecContainerMonitor{}).Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "id"}},
				DoUpdates: clause.AssignmentColumns(onDupUpdatedForContainerClusterMangerStatus),
			}).Create(&containers).Error
		} else {
			err = tx.Model(&model.TensorsecContainerMonitor{}).Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "id"}},
				DoUpdates: clause.AssignmentColumns(onDupUpdatedForContainerStatus),
			}).Create(&containers).Error
		}
		if err != nil {
			return err
		}
		if isHolmes {
			var healthV int
			if isHealth == false {
				healthV = 1
			}
			// todo
			logging.Get().Info().Msgf("UpsertContainerStatus holmes  pod_is_health:%d, podName:%s", healthV, containers[0].PodName)
			return tx.Model(&model.TensorsecContainerMonitor{}).Where("pod_name = ? and container_name = 'daemon'", containers[0].PodName).Update("pod_is_health", healthV).Error
		}
		return nil
	}
	if dbIsTx {
		return dbFunc(rdb)
	}
	return rdb.WithContext(ctx).Transaction(dbFunc)
}

func UpsertClusterManagerHeartbeat(ctx context.Context, rdb *gorm.DB, container *model.TensorsecContainerMonitor) error {
	return rdb.WithContext(ctx).Model(&model.TensorsecContainerMonitor{}).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns(onDupUpdatedForContainerStatus),
	}).Create(container).Error

}

func DeleteContainerStatusByPodName(ctx context.Context, rdb *gorm.DB, podName string) (affected int64, error error) {
	if len(podName) == 0 {
		return 0, nil
	}
	result := rdb.WithContext(ctx).Where("pod_name =  ?", podName).Delete(&model.TensorsecContainerMonitor{})
	return result.RowsAffected, result.Error
}
func DeleteContainerStatusByIds(ctx context.Context, rdb *gorm.DB, ids []uint32) (affected int64, error error) {
	if len(ids) == 0 {
		return 0, nil
	}
	result := rdb.WithContext(ctx).Where("id  in  ?", ids).Delete(&model.TensorsecContainerMonitor{})
	return result.RowsAffected, result.Error
}

func CleanExpireContainerStatus(ctx context.Context, rdb *gorm.DB, clusterKey string, ts time.Time, appLabel string, nodeName string) {
	db := rdb.WithContext(ctx).Where("updated_at < ? AND cluster_key = ?", ts.Add(-time.Millisecond), clusterKey)
	if appLabel != "" {
		db = db.Where("app_label = ?", appLabel)
	}
	if nodeName != "" {
		db = db.Where("node_name = ?", nodeName)
	}
	err := db.Delete(&model.TensorsecContainerMonitor{}).Error

	if err != nil {
		logging.Get().Err(err).Msg("monitor: AfterDataSynced failed.")
	}
}

func GetSoftVersionFromAssetsByKeyAndNs(ctx context.Context, rdb *gorm.DB, clusterKey string, namespace string) string {
	var rawContainer model.TensorRawContainer
	err := rdb.WithContext(ctx).Where("cluster_key = ? and namespace = ? and pod_name like ? and status=0",
		clusterKey, namespace, GetLikeExpr(AppLabel_clusterManager)).Select("environment").Take(&rawContainer).Error
	if err != nil {
		logging.Get().Err(err).Msgf("get env from rawContainer failed.clusterKey:%s,namespace:%s", clusterKey, namespace)
		return ""
	}
	for _, str := range rawContainer.Environment {
		if strings.Contains(str, env.SoftVersionEnv) {
			return str[len(env.SoftVersionEnv)+1:]
		}
	}
	return ""
}

type OldMetrics struct {
	ID                    uint32    `gorm:"column:id;type:bigint;primaryKey" json:"id,omitempty"`
	CpuUsageCurrent       uint64    `json:"cpuUsageCurrent" gorm:"column:cpu_usage_current"`
	CpuSystemUsageCurrent uint64    `json:"cpuSystemUsageCurrent" gorm:"column:cpu_system_usage_current"`
	MemCurrent            uint64    `json:"memCurrent" gorm:"column:mem_current"`
	BlockICurrent         uint64    `json:"blockICurrent" gorm:"column:block_i_current"`
	BlockOCurrent         uint64    `json:"blockOCurrent" gorm:"column:block_o_current"`
	MetricsLastTime       time.Time `json:"metricsLastTime" gorm:"column:metrics_last_time"`
}

func GetOldMetricsMap(ctx context.Context, rdb *gorm.DB, ids []uint32) (map[uint32]OldMetrics, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	tctx, cancelFunc := context.WithTimeout(ctx, 3*time.Second)
	defer cancelFunc()
	var oldMetricsData []model.TensorsecContainerMonitor
	err := rdb.WithContext(tctx).Model(&model.TensorsecContainerMonitor{}).Where("id in ?", ids).
		Select("id", "cpu_usage_current", "cpu_system_usage_current", "mem_current", "block_i_current", "block_o_current", "metrics_last_time").Find(&oldMetricsData).Error
	if err != nil {
		return nil, err
	}
	result := make(map[uint32]OldMetrics)
	for _, metrics := range oldMetricsData {
		result[metrics.ID] = OldMetrics{
			ID:                    metrics.ID,
			CpuUsageCurrent:       metrics.CpuUsageCurrent,
			CpuSystemUsageCurrent: metrics.CpuSystemUsageCurrent,
			MemCurrent:            metrics.MemCurrent,
			BlockICurrent:         metrics.BlockICurrent,
			BlockOCurrent:         metrics.BlockOCurrent,
			MetricsLastTime:       metrics.MetricsLastTime,
		}
	}
	return result, nil
}

func UpsertContainerMetrics(ctx context.Context, rdb *gorm.DB, containers []*model.TensorsecContainerMonitor, clusterMangerContainers []*model.TensorsecContainerMonitor) error {
	return rdb.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if len(clusterMangerContainers) > 0 { // 不更新心跳时间
			err := tx.WithContext(ctx).Model(&model.TensorsecContainerMonitor{}).Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "id"}},
				DoUpdates: clause.AssignmentColumns(onDupUpdatedForContainerClusterManagerMetrics),
			}).Create(clusterMangerContainers).Error
			if err != nil {
				return err
			}
		}

		if len(containers) > 0 {
			err := tx.Model(&model.TensorsecContainerMonitor{}).Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "id"}},
				DoUpdates: clause.AssignmentColumns(onDupUpdatedForContainerMetrics),
			}).Create(containers).Error
			if err != nil {
				return err
			}
		}
		return nil
	})
}

type MonitorTotal struct {
	HolmesContainerTotal      int32
	HolmesContainerRunning    int32
	HolmesContainerNotRunning int32

	ClusterManagerPodTotal      int32
	ClusterManagerPodRunning    int32
	ClusterManagerPodNotRunning int32

	ScannerPodTotal      int32
	ScannerPodRunning    int32
	ScannerPodNotRunning int32
}

type MonitorCount struct {
	AppLabel string
	Total    int32
	Running  int32
}

func GetMonitorTotal(ctx context.Context, rdb *gorm.DB) (*MonitorTotal, error) {
	//db.Model(&User{}).Select("name, sum(age) as total").Group("name").Having("name = ?", "group").Find(&result)
	var totalList []MonitorCount
	err := rdb.Model(&model.TensorsecContainerMonitor{}).Select("app_label,count(*) as total ,SUM(CASE WHEN container_status = 0 THEN 1 ELSE 0 END) as running").Group("app_label").Find(&totalList).Error
	if err != nil {
		logging.Get().Err(err).Msg("GetMonitorTotal failed.")
	}
	var result MonitorTotal
	for _, count := range totalList {
		switch count.AppLabel {
		case AppLabel_holmes:
			result.HolmesContainerTotal = count.Total
			result.HolmesContainerRunning = count.Running
			result.HolmesContainerNotRunning = count.Total - count.Running
		case AppLabel_scanner:
			result.ScannerPodTotal = count.Total
			result.ScannerPodRunning = count.Running
			result.ScannerPodNotRunning = count.Total - count.Running
		case AppLabel_clusterManager:
			result.ClusterManagerPodTotal = count.Total
			result.ClusterManagerPodRunning = count.Running
			result.ClusterManagerPodNotRunning = count.Total - count.Running
		}
	}
	return &result, nil

}

type MonitorOption struct {
	WhereEqCondition   map[string]any
	WhereInCondition   map[string]any
	WhereLikeCondition map[string]string
}

func NewMonitorOption() *MonitorOption {
	return &MonitorOption{
		WhereEqCondition:   make(map[string]any, 3),
		WhereInCondition:   make(map[string]any, 3),
		WhereLikeCondition: make(map[string]string, 2),
	}
}

type MonitorHolmesResp struct {
	PodName          string            `json:"podName"`
	Version          string            `json:"version"`
	PodStatus        string            `json:"podStatus"`
	ContainerTotal   int32             `json:"containerTotal"`
	ContainerRunning int32             `json:"containerRunning"`
	ClusterKey       string            `json:"clusterKey"`
	NodeName         string            `json:"nodeName"`
	ContainerData    []*MonitorHolmesC `json:"containerData"`
}
type MonitorHolmesC struct {
	ContainerName   string `json:"containerName"`
	ContainerStatus string `json:"containerStatus"`
	Cpu             string `json:"cpu"`
	Mem             string `json:"mem"`
	BlockIO         string `json:"blockIO"`
	//MetricsTime     time.Time `json:"metricsTime"`
	MetricsTimeStamp int64 `json:"metricsTimeStamp"` // 微秒
}

func GetMonitorHolmesPod(ctx context.Context, rdb *gorm.DB, queryOpt *MonitorOption, offset, limit int) ([]*MonitorHolmesResp, error) {
	pgCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	db := rdb.Where("container_name = 'daemon'")
	if len(queryOpt.WhereEqCondition) > 0 {
		db = db.Where(queryOpt.WhereEqCondition)
	}
	for k, v := range queryOpt.WhereLikeCondition {
		db = db.Where(fmt.Sprintf("%s like ?", k), GetLikeExpr(v))
	}
	for column, val := range queryOpt.WhereInCondition {
		db = db.Where(fmt.Sprintf("%s in ?", column), val)
	}
	if limit > 0 && offset >= 0 {
		db = db.Offset(offset).Limit(limit)
	}
	db.Order("pod_is_health DESC")
	var containerMonitors []*model.TensorsecContainerMonitor
	var targetNodeName []string
	err := db.WithContext(pgCtx).Model(&model.TensorsecContainerMonitor{}).Select("node_name").Find(&targetNodeName).Error
	if err != nil {
		logging.Get().Err(err).Msg("GetMonitorHolmesPod failed.")
		return nil, err
	}
	if len(targetNodeName) == 0 {
		return nil, nil
	}
	err = rdb.WithContext(pgCtx).Model(&model.TensorsecContainerMonitor{}).Where(fmt.Sprintf("app_label = '%s'", AppLabel_holmes)).Where("node_name in ?", targetNodeName).Order("pod_is_health DESC,container_status").Find(&containerMonitors).Error
	var result []*MonitorHolmesResp

	podNameMap := make(map[string]*MonitorHolmesResp)
	for _, monitor := range containerMonitors {
		old, isOK := podNameMap[monitor.PodName]
		if !isOK {
			item := MonitorHolmesResp{
				PodName:    monitor.PodName,
				Version:    monitor.Version,
				ClusterKey: monitor.ClusterKey,
				NodeName:   monitor.NodeName,
			}
			old = &item
			podNameMap[monitor.PodName] = &item
			result = append(result, &item)
		}
		tmpContainer := MonitorHolmesC{
			ContainerName:    monitor.ContainerName,
			MetricsTimeStamp: monitor.MetricsLastTime.UnixMilli(),
		}
		tmpContainer.Cpu = getCpu(monitor.CpuUsageLast, monitor.CpuUsageCurrent, monitor.CpuSystemUsageLast, monitor.CpuSystemUsageCurrent, monitor.OnlineCpus, float64(monitor.CpuLimit), monitor.TimeGap)
		tmpContainer.Mem = getMem(monitor.MemCurrent)
		tmpContainer.BlockIO = getBlockIO(monitor.BlockILast, monitor.BlockICurrent, monitor.BlockOLast, monitor.BlockOCurrent, monitor.TimeGap)
		if monitor.ContainerStatus == ContainerState_running {
			tmpContainer.ContainerStatus = ContainerStatus_normal
			old.ContainerRunning++
		} else {
			tmpContainer.ContainerStatus = ContainerStatus_abnormal
		}
		old.ContainerData = append(old.ContainerData, &tmpContainer)
		old.ContainerTotal++
	}
	for _, item := range result {
		if item.ContainerTotal == item.ContainerRunning {
			item.PodStatus = ContainerStatus_normal
		} else {
			item.PodStatus = ContainerStatus_abnormal
		}
	}

	return result, nil

}

func GetMonitorHolmesPodTotal(ctx context.Context, rdb *gorm.DB, queryOpt *MonitorOption) (int64, error) {
	pgCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	db := rdb.Where("container_name = 'daemon'")
	if len(queryOpt.WhereEqCondition) > 0 {
		db = db.Where(queryOpt.WhereEqCondition)
	}
	for k, v := range queryOpt.WhereLikeCondition {
		db = db.Where(fmt.Sprintf("%s like ?", k), GetLikeExpr(v))
	}
	for column, val := range queryOpt.WhereInCondition {
		db = db.Where(fmt.Sprintf("%s in ?", column), val)
	}
	var total int64
	err := db.WithContext(pgCtx).Model(&model.TensorsecContainerMonitor{}).Count(&total).Error
	return total, err
}

type MonitorComponentResp struct {
	PodName string `json:"podName"`
	//Version          string `json:"version"`
	PodStatus  string `json:"podStatus"`
	ClusterKey string `json:"clusterKey"`
	NodeName   string `json:"nodeName"`
	Cpu        string `json:"cpu"`
	Mem        string `json:"mem"`
	BlockIO    string `json:"blockIO"`
	//LastUpdateTime time.Time `json:"lastUpdateTime"`
	LastUpdateTimeStamp int64 `json:"lastUpdateTimeStamp"`
}

func GetMonitorComponentPod(ctx context.Context, rdb *gorm.DB, queryOpt *MonitorOption, offset, limit int) ([]*MonitorComponentResp, error) {
	pgCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	component := queryOpt.WhereEqCondition["app_label"]
	db := rdb.Order("container_status ASC")
	if len(queryOpt.WhereEqCondition) > 0 {
		db = db.Where(queryOpt.WhereEqCondition)
	}
	for k, v := range queryOpt.WhereLikeCondition {
		db = db.Where(fmt.Sprintf("%s like ?", k), GetLikeExpr(v))
	}
	for column, val := range queryOpt.WhereInCondition {
		db = db.Where(fmt.Sprintf("%s in ?", column), val)
	}
	if limit > 0 && offset >= 0 {
		db = db.Offset(offset).Limit(limit)
	}

	var containermonitors []model.TensorsecContainerMonitor
	err := db.WithContext(pgCtx).Find(&containermonitors).Error
	if err != nil {
		return nil, err
	}

	var result []*MonitorComponentResp
	for _, c := range containermonitors {
		item := MonitorComponentResp{
			PodName:    c.PodName,
			ClusterKey: c.ClusterKey,
			NodeName:   c.NodeName,
			//LastUpdateTime: c.UpdatedAt,
			LastUpdateTimeStamp: c.UpdatedAt.UnixMilli(),
		}

		item.Cpu = getCpu(c.CpuUsageLast, c.CpuUsageCurrent, c.CpuSystemUsageLast, c.CpuSystemUsageCurrent, c.OnlineCpus, float64(c.CpuLimit), c.TimeGap)
		item.Mem = getMem(c.MemCurrent)
		item.BlockIO = getBlockIO(c.BlockILast, c.BlockICurrent, c.BlockOLast, c.BlockOCurrent, c.TimeGap)
		if component == AppLabel_clusterManager {
			if c.Version < "2.21" { //old
				if c.ContainerStatus == ContainerState_running {
					item.PodStatus = ContainerStatus_normal
				} else {
					item.PodStatus = ContainerStatus_abnormal
				}
			} else { //cluster-manager 引入心跳
				// 当前距离上次心跳时间超过2分，则视为异常
				if time.Now().Sub(c.UpdatedAt).Minutes() >= 2 {
					item.PodStatus = ContainerStatus_abnormal
				} else {
					item.PodStatus = ContainerStatus_normal
				}
			}
		} else {
			if c.ContainerStatus == ContainerState_running {
				item.PodStatus = ContainerStatus_normal
			} else {
				item.PodStatus = ContainerStatus_abnormal
			}
		}
		result = append(result, &item)
	}
	return result, nil
}
func GetMonitorComponentPodTotal(ctx context.Context, rdb *gorm.DB, queryOpt *MonitorOption) (int64, error) {
	pgCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	db := rdb
	if len(queryOpt.WhereEqCondition) > 0 {
		db = db.Where(queryOpt.WhereEqCondition)
	}
	for k, v := range queryOpt.WhereLikeCondition {
		db = db.Where(fmt.Sprintf("%s like ?", k), GetLikeExpr(v))
	}
	for column, val := range queryOpt.WhereInCondition {
		db = db.Where(fmt.Sprintf("%s in ?", column), val)
	}
	var total int64
	err := db.WithContext(pgCtx).Model(&model.TensorsecContainerMonitor{}).Count(&total).Error
	return total, err
}

func getBlockIO(blockILast uint64, blockICurrent uint64, blockOLast uint64, blockOCurrent uint64, dur int64) string {
	if dur == 0 { // 首次
		return ""
	}
	totalBytes := int(blockOCurrent + blockICurrent - blockOLast - blockILast)
	if totalBytes == 0 {
		return "0.0B/S"
	}
	//  1s= 10^6 us 微秒
	bytePers := float64(totalBytes) / float64(dur) * 1000000
	logging.Get().Info().Msgf("float64(%d) / float64(%d) * float64(time.Second)  = %f", totalBytes, dur, bytePers)
	if bytePers <= 1024 {
		return fmt.Sprintf("%.1fB/S", bytePers)
	}
	if bytePers <= 1024*1024 {
		mbs, _ := decimal.NewFromFloat(float64(bytePers) / (1024)).Round(2).Float64()
		return fmt.Sprintf("%.1fKB/S", mbs)
	}
	if bytePers <= 1024*1024*1024 {
		mbs, _ := decimal.NewFromFloat(float64(bytePers) / (1024 * 1024)).Round(2).Float64()
		return fmt.Sprintf("%.1fMB/S", mbs)
	}
	mbs, _ := decimal.NewFromFloat(float64(bytePers) / (1024 * 1024 * 1024)).Round(2).Float64()
	return fmt.Sprintf("%.1fGB/S", mbs)
}

func getCpu(cpuTotalLast, cpuTotalCurrent uint64, cpuSystemTotalLast uint64, cpuSystemTotalCurrent uint64, OnlineCpu uint32, limit float64, dur int64) string {
	if dur == 0 { //没有上次的记录
		return ""
	}
	cpuPercent := 0.0

	var (
		// calculate the change for the cpu usage of the container in between readings
		cpuDelta = float64(cpuTotalCurrent) - float64(cpuTotalLast)
		// calculate the change for the entire system between readings
		systemDelta = float64(cpuSystemTotalCurrent) - float64(cpuSystemTotalLast)
	)

	if systemDelta > 0.0 && cpuDelta > 0.0 { //docker
		cpuPercent = (cpuDelta / systemDelta) * float64(OnlineCpu) * 100.0
	}

	if cpuPercent > 0.0 {
		return fmt.Sprintf("%.1f%%", cpuPercent)
	}

	//	case2    微秒 单位
	rate := cpuDelta / float64(dur)
	if limit > 0.0 {
		cpuPercent = (rate / limit) * 100.0
	}
	return fmt.Sprintf("%.1f%%", cpuPercent)

}

func getMem(memoryByte uint64) string {
	if memoryByte == 0 {
		return ""
	}
	rate := float64(memoryByte) / (1024 * 1024)
	return fmt.Sprintf("%.1fMB", rate)
}

func getK8sClient(_ context.Context, clusterKey string) (*pkgasserts.Clientset, error) {
	clusterManager, ok := k8s.GetClusterManager()
	if !ok {
		return nil, errors.New("get cluster falied")
	}

	// get client
	k8sClient, ok := clusterManager.GetClient(clusterKey)
	if !ok {
		return nil, errors.New("get k8s client error")
	}

	return k8sClient, nil
}
