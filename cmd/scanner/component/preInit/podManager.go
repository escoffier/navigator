package preinit

import (
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"time"

	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	certutil "k8s.io/client-go/util/cert"
)

// PodManager manages Pod operations
type PodManager struct {
	clusterDal imagesecStore.ResourceDal
	log        *scannerUtils.LogEvent
}

// NewPodManager creates a new PodManager
func NewPodManager(clusterDal imagesecStore.ResourceDal) *PodManager {
	return &PodManager{
		clusterDal: clusterDal,
		log:        scannerUtils.NewLogEvent(scannerUtils.WithModule("PodManager")),
	}
}

// getClusterConfig gets REST configuration based on cluster information
func (pm *PodManager) getClusterConfig(ctx context.Context, cluster *model.TensorCluster) (*rest.Config, error) {
	// Create REST configuration based on cluster information
	tlsClientConfig := rest.TLSClientConfig{Insecure: false}

	// Configure CA certificate
	ca := []byte(cluster.CertificateAuthData)
	_, err := certutil.NewPoolFromBytes(ca)
	if err != nil {
		tlsClientConfig.Insecure = true
		pm.log.Err(err).
			Str("cluster_key", cluster.Key).
			Str("cluster_name", cluster.Name).
			Msg("Invalid CA certificate, setting Insecure=true")
	} else {
		tlsClientConfig.CAData = ca
	}

	// Configure client certificate authentication (if no token provided)
	if cluster.SecretToken == "" {
		tlsClientConfig.CertData = []byte(cluster.ClientCertData)
		tlsClientConfig.KeyData = []byte(cluster.ClientKeyData)
		pm.log.Info().
			Str("cluster_key", cluster.Key).
			Str("cluster_name", cluster.Name).
			Msg("Using client certificate authentication")
	} else {
		pm.log.Info().
			Str("cluster_key", cluster.Key).
			Str("cluster_name", cluster.Name).
			Msg("Using token authentication")
	}

	config := &rest.Config{
		Host:            cluster.APIServerAddr,
		TLSClientConfig: tlsClientConfig,
		BearerToken:     cluster.SecretToken,
	}

	return config, nil
}

func CreateClient(ctx context.Context, cluster *model.TensorCluster) (*kubernetes.Clientset, error) {
	serverName := os.Getenv("KUBE_SERVER_NAME")
	if serverName == "" {
		serverName = "kubernetes"
	}
	tlsClientConfig := rest.TLSClientConfig{Insecure: false, ServerName: serverName}
	ca := []byte(cluster.CertificateAuthData)
	_, err := certutil.NewPoolFromBytes(ca)
	if err != nil {
		tlsClientConfig.Insecure = true
	} else {
		tlsClientConfig.CAData = ca
	}

	if cluster.SecretToken == "" {
		tlsClientConfig.CertData = []byte(cluster.ClientCertData)
		tlsClientConfig.KeyData = []byte(cluster.ClientKeyData)
	}
	clientSet, err := kubernetes.NewForConfig(&rest.Config{
		Host:            cluster.APIServerAddr,
		TLSClientConfig: tlsClientConfig,
		BearerToken:     cluster.SecretToken,
	})
	if err != nil {
		return nil, err
	}
	return clientSet, nil
}

// createClient creates a kubernetes client
func (pm *PodManager) createClient(ctx context.Context, config *rest.Config) (*kubernetes.Clientset, error) {
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %v", err)
	}
	return clientset, nil
}

// ListNamespacePods gets the list of Pods in the specified namespace
func (pm *PodManager) ListNamespacePods(ctx context.Context, cluster *model.TensorCluster, namespace string) ([]corev1.Pod, error) {
	// config, err := pm.getClusterConfig(ctx, cluster)
	// if err != nil {
	// 	return nil, err
	// }
	//
	// client, err := pm.createClient(ctx, config)
	// if err != nil {
	// 	return nil, err
	// }

	client, err := CreateClient(ctx, cluster)
	if err != nil {
		pm.log.Err(err).
			Str("cluster_key", cluster.Key).
			Str("cluster_name", cluster.Name).
			Interface("cluster", cluster).
			Msg("Failed to create client")
		return nil, err
	}

	reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	pm.log.Info().
		Str("cluster_key", cluster.Key).
		Str("cluster_name", cluster.Name).
		Str("namespace", namespace).
		Msg("Listing pods in namespace")

	pods, err := client.CoreV1().Pods(namespace).List(reqCtx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list pods in namespace %s: %v", namespace, err)
	}

	pm.log.Info().
		Str("cluster_key", cluster.Key).
		Str("cluster_name", cluster.Name).
		Str("namespace", namespace).
		Int("pod_count", len(pods.Items)).
		Msg("Successfully retrieved pods from namespace")

	return pods.Items, nil
}

// writeClusterToCSV writes cluster information to a CSV file
func (pm *PodManager) writeClusterToCSV(ctx context.Context, clusters []*model.TensorCluster, filePath string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %v", dir, err)
	}

	// Create CSV file
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create CSV file: %v", err)
	}
	defer func() { _ = file.Close() }()

	// Create CSV writer
	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write CSV header
	headers := []string{"ClusterKey", "ClusterName"}
	if err := writer.Write(headers); err != nil {
		return fmt.Errorf("failed to write CSV header: %v", err)
	}

	// Write each cluster's information
	for _, cluster := range clusters {
		record := []string{
			cluster.Key,
			cluster.Name,
		}

		if err := writer.Write(record); err != nil {
			pm.log.Err(err).
				Str("cluster_key", cluster.Key).
				Str("cluster_name", cluster.Name).
				Msg("Failed to write cluster information to CSV")
			continue
		}
	}

	pm.log.Info().
		Str("file_path", filePath).
		Int("cluster_count", len(clusters)).
		Msg("Successfully wrote cluster information to CSV file")

	return nil
}

// readClusterFromCSV reads cluster information from a CSV file
func (pm *PodManager) readClusterFromCSV(ctx context.Context, filePath string) (map[string]string, error) {
	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return make(map[string]string), nil
	}

	// Open CSV file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open CSV file: %v", err)
	}
	defer func() { _ = file.Close() }()

	// Create CSV reader
	reader := csv.NewReader(file)

	// Read all records
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to read CSV file: %v", err)
	}

	// Skip header
	if len(records) > 0 {
		records = records[1:]
	}

	// Create map of cluster keys to names
	clusterMap := make(map[string]string)
	for _, record := range records {
		if len(record) >= 2 {
			clusterMap[record[0]] = record[1]
		}
	}

	pm.log.Info().
		Str("file_path", filePath).
		Int("cluster_count", len(clusterMap)).
		Msg("Successfully read cluster information from CSV file")

	return clusterMap, nil
}

// appendClusterToCSV appends a cluster to the success CSV file
func (pm *PodManager) appendClusterToCSV(ctx context.Context, cluster *model.TensorCluster, filePath string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %v", dir, err)
	}

	// Check if file exists
	fileExists := true
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		fileExists = false
	}

	// Open file in append mode
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open CSV file: %v", err)
	}
	defer func() { _ = file.Close() }()

	// Create CSV writer
	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header if file doesn't exist
	if !fileExists {
		headers := []string{"ClusterKey", "ClusterName"}
		if err := writer.Write(headers); err != nil {
			return fmt.Errorf("failed to write CSV header: %v", err)
		}
	}

	// Write cluster information
	record := []string{
		cluster.Key,
		cluster.Name,
	}

	if err := writer.Write(record); err != nil {
		return fmt.Errorf("failed to write cluster information to CSV: %v", err)
	}

	pm.log.Info().
		Str("file_path", filePath).
		Str("cluster_key", cluster.Key).
		Str("cluster_name", cluster.Name).
		Msg("Successfully appended cluster to CSV file")

	return nil
}

// calculatePodAge calculates the age of a pod
func (pm *PodManager) calculatePodAge(pod corev1.Pod) string {
	creationTime := pod.GetCreationTimestamp().Time
	age := time.Since(creationTime)

	// Format age in a human-readable format
	if age.Hours() > 24 {
		days := int(age.Hours() / 24)
		return fmt.Sprintf("%dd", days)
	} else if age.Hours() > 1 {
		return fmt.Sprintf("%dh", int(age.Hours()))
	} else if age.Minutes() > 1 {
		return fmt.Sprintf("%dm", int(age.Minutes()))
	} else {
		return fmt.Sprintf("%ds", int(age.Seconds()))
	}
}

// ExportPodsToCSV exports Pod information from all clusters in the specified namespace to a CSV file
func (pm *PodManager) ExportPodsToCSV(ctx context.Context, namespace, filePath string) error {
	// Get all clusters
	clusters, err := pm.clusterDal.SearchCluster(ctx)
	if err != nil {
		pm.log.Error().Err(err).Msg("Failed to retrieve clusters")
		return err
	}

	pm.log.Info().
		Int("cluster_count", len(clusters)).
		Str("namespace", namespace).
		Msg("Starting pod export process")

	// 准备文件路径
	paths := pm.prepareFilePaths(filePath)

	// 初始化导出文件
	if err := pm.initExportFiles(ctx, clusters, paths); err != nil {
		return err
	}

	// 读取已成功处理的集群
	successfulClusters, err := pm.readClusterFromCSV(ctx, paths.successPath)
	if err != nil {
		pm.log.Error().
			Err(err).
			Str("file_path", paths.successPath).
			Msg("Failed to read successful clusters from CSV")
		return err
	}

	// 准备数据文件
	dataFile, writer, _, err := pm.prepareDataFile(paths.dataPath)
	if err != nil {
		return err
	}
	defer func() { _ = dataFile.Close() }()
	defer writer.Flush()

	// 处理所有集群
	stats := pm.processAllClusters(ctx, clusters, successfulClusters, namespace, writer, paths)

	// 记录导出结果
	pm.logExportResults(filePath, namespace, len(clusters), stats)

	return nil
}

// 文件路径结构体
type exportFilePaths struct {
	clusterPath string
	successPath string
	dataPath    string
	failedPath  string
}

// prepareFilePaths 准备所有需要的文件路径
func (pm *PodManager) prepareFilePaths(baseFilePath string) exportFilePaths {
	return exportFilePaths{
		clusterPath: filepath.Join(baseFilePath, "cluster.csv"),
		successPath: filepath.Join(baseFilePath, "success.csv"),
		dataPath:    filepath.Join(baseFilePath, "data.csv"),
		failedPath:  filepath.Join(baseFilePath, "failed.csv"),
	}
}

// initExportFiles 初始化导出所需的文件
func (pm *PodManager) initExportFiles(ctx context.Context, clusters []*model.TensorCluster, paths exportFilePaths) error {
	// 初始化 cluster.csv
	if err := pm.initClusterFile(ctx, clusters, paths.clusterPath); err != nil {
		return err
	}

	// 初始化 failed.csv
	if err := pm.initFailedFile(paths.failedPath); err != nil {
		return err
	}

	return nil
}

// initClusterFile 初始化集群文件
func (pm *PodManager) initClusterFile(ctx context.Context, clusters []*model.TensorCluster, filePath string) error {
	// 删除并重新创建 cluster.csv
	_ = os.Remove(filePath)
	if err := pm.writeClusterToCSV(ctx, clusters, filePath); err != nil {
		pm.log.Error().
			Err(err).
			Str("file_path", filePath).
			Msg("Failed to write cluster information to CSV")
		return err
	}
	return nil
}

// initFailedFile 初始化失败记录文件
func (pm *PodManager) initFailedFile(filePath string) error {
	// 删除并重新创建 failed.csv
	_ = os.Remove(filePath)

	// 创建目录（如果不存在）
	failedDir := filepath.Dir(filePath)
	if err := os.MkdirAll(failedDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %v", failedDir, err)
	}

	// 创建 failed.csv 文件
	failedFile, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create failed CSV file: %v", err)
	}
	defer failedFile.Close()

	// 写入 failed.csv 头部
	failedWriter := csv.NewWriter(failedFile)
	if err := failedWriter.Write([]string{"ClusterKey", "ClusterName", "ErrorMessage"}); err != nil {
		return fmt.Errorf("failed to write failed CSV header: %v", err)
	}
	failedWriter.Flush()

	return nil
}

// prepareDataFile 准备数据文件
func (pm *PodManager) prepareDataFile(filePath string) (*os.File, *csv.Writer, bool, error) {
	var dataFile *os.File
	var err error
	dataFileExists := false

	// 检查 data.csv 是否存在
	if _, err := os.Stat(filePath); err == nil {
		dataFileExists = true
	}

	// 打开或创建 data.csv
	if dataFileExists {
		dataFile, err = os.OpenFile(filePath, os.O_APPEND|os.O_WRONLY, 0644)
	} else {
		// 创建目录（如果不存在）
		dataDir := filepath.Dir(filePath)
		if err := os.MkdirAll(dataDir, 0755); err != nil {
			return nil, nil, false, fmt.Errorf("failed to create directory %s: %v", dataDir, err)
		}
		dataFile, err = os.Create(filePath)
	}

	if err != nil {
		return nil, nil, false, fmt.Errorf("failed to open/create data CSV file: %v", err)
	}

	// 创建 CSV writer
	writer := csv.NewWriter(dataFile)

	// 如果是新文件，写入 CSV 头部
	if !dataFileExists {
		headers := []string{"ClusterName", "PodName", "PodIP", "PodStatus", "NodeName", "Age", "Namespace"}
		if err := writer.Write(headers); err != nil {
			dataFile.Close()
			return nil, nil, false, fmt.Errorf("failed to write CSV header: %v", err)
		}
	}

	return dataFile, writer, dataFileExists, nil
}

// 导出统计信息
type exportStats struct {
	successCount int
	failureCount int
	skipCount    int
}

// processAllClusters 处理所有集群
func (pm *PodManager) processAllClusters(
	ctx context.Context,
	clusters []*model.TensorCluster,
	successfulClusters map[string]string,
	namespace string,
	writer *csv.Writer,
	paths exportFilePaths,
) exportStats {
	stats := exportStats{
		skipCount: len(successfulClusters),
	}

	// 处理每个集群
	for _, cluster := range clusters {
		// 跳过已处理的集群
		if _, exists := successfulClusters[cluster.Key]; exists {
			pm.log.Info().
				Str("cluster_key", cluster.Key).
				Str("cluster_name", cluster.Name).
				Msg("Skipping already processed cluster")
			continue
		}

		success := pm.processCluster(ctx, cluster, namespace, writer, paths.failedPath, paths.successPath)
		if success {
			stats.successCount++
		} else {
			stats.failureCount++
		}
	}

	return stats
}

// processCluster 处理单个集群
func (pm *PodManager) processCluster(
	ctx context.Context,
	cluster *model.TensorCluster,
	namespace string,
	writer *csv.Writer,
	failedPath string,
	successPath string,
) bool {
	pm.log.Info().
		Str("cluster_key", cluster.Key).
		Str("cluster_name", cluster.Name).
		Str("namespace", namespace).
		Msg("Processing cluster")

	// 获取此集群的 pod
	pods, err := pm.ListNamespacePods(ctx, cluster, namespace)
	if err != nil {
		pm.log.Error().
			Err(err).
			Str("cluster_key", cluster.Key).
			Str("cluster_name", cluster.Name).
			Str("namespace", namespace).
			Msg("Failed to retrieve pod list, skipping cluster")

		// 记录失败的集群到 failed.csv
		if err := pm.appendFailedClusterToCSV(ctx, cluster, err.Error(), failedPath); err != nil {
			pm.log.Error().
				Err(err).
				Str("cluster_key", cluster.Key).
				Str("cluster_name", cluster.Name).
				Str("file_path", failedPath).
				Msg("Failed to write to failed.csv")
		}

		return false
	}

	// 写入每个 pod 的信息
	podCount := pm.writePodRecords(cluster, pods, writer)

	// 标记集群为成功处理
	if err := pm.appendClusterToCSV(ctx, cluster, successPath); err != nil {
		pm.log.Error().
			Err(err).
			Str("cluster_key", cluster.Key).
			Str("cluster_name", cluster.Name).
			Str("file_path", successPath).
			Msg("Failed to mark cluster as processed")
	}

	pm.log.Info().
		Str("cluster_key", cluster.Key).
		Str("cluster_name", cluster.Name).
		Str("namespace", namespace).
		Int("pod_count", podCount).
		Msg("Successfully processed cluster")

	return true
}

// writePodRecords 写入Pod记录
func (pm *PodManager) writePodRecords(
	cluster *model.TensorCluster,
	pods []corev1.Pod,
	writer *csv.Writer,
) int {
	podCount := 0
	for _, pod := range pods {
		podIP := ""
		if pod.Status.PodIP != "" {
			podIP = pod.Status.PodIP
		}

		age := pm.calculatePodAge(pod)

		record := []string{
			cluster.Name,
			pod.Name,
			podIP,
			string(pod.Status.Phase),
			pod.Spec.NodeName,
			age,
			pod.Namespace,
		}

		if err := writer.Write(record); err != nil {
			pm.log.Error().
				Err(err).
				Str("cluster_key", cluster.Key).
				Str("cluster_name", cluster.Name).
				Str("pod_name", pod.Name).
				Msg("Failed to write pod information")
			continue
		}
		podCount++
	}
	return podCount
}

// logExportResults 记录导出结果
func (pm *PodManager) logExportResults(filePath, namespace string, totalClusters int, stats exportStats) {
	pm.log.Info().
		Str("file_path", filePath).
		Str("namespace", namespace).
		Int("total_clusters", totalClusters).
		Int("successful_clusters", stats.successCount).
		Int("failed_clusters", stats.failureCount).
		Int("skipped_clusters", stats.skipCount).
		Msg("Pod export process completed")

	// 检查是否所有集群都已处理
	if stats.successCount+stats.skipCount == totalClusters {
		pm.log.Info().Msg("All clusters have been successfully processed")
	} else {
		pm.log.Error().
			Int("remaining_clusters", totalClusters-(stats.successCount+stats.skipCount)).
			Msg("Some clusters failed to process, restart required to complete")
	}
}

// appendFailedClusterToCSV 将失败的集群信息追加到 failed.csv 文件
func (pm *PodManager) appendFailedClusterToCSV(ctx context.Context, cluster *model.TensorCluster, errorMsg string, filePath string) error {
	// 创建目录（如果不存在）
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %v", dir, err)
	}

	// 以追加模式打开文件
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open failed CSV file: %v", err)
	}
	defer func() { _ = file.Close() }()

	// 创建 CSV writer
	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 写入集群信息
	record := []string{
		cluster.Key,
		cluster.Name,
		errorMsg,
	}

	if err := writer.Write(record); err != nil {
		return fmt.Errorf("failed to write failed cluster information to CSV: %v", err)
	}

	pm.log.Info().
		Str("file_path", filePath).
		Str("cluster_key", cluster.Key).
		Str("cluster_name", cluster.Name).
		Msg("Successfully appended failed cluster to CSV file")

	return nil
}

// CollectAndExportPods collects and exports all Pod information in the anquan namespace
func (pm *PodManager) CollectAndExportPods(ctx context.Context, ns string, fp string) error {
	pm.log.Info().Str("namespace", ns).Msg("Starting collection of pods")
	err := pm.ExportPodsToCSV(ctx, ns, fp)
	if err != nil {
		pm.log.Error().
			Err(err).Str("namespace", ns).
			Msg("Failed to export pods")
		return err
	}
	pm.log.Info().Msg("Successfully completed pod collection")
	return nil
}
