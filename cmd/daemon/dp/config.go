package dp

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	// "runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	// json "github.com/json-iterator/go"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/dp/whitelist"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

type WhiteListScannerState uint32

const (
	WhiteListNotReady = WhiteListScannerState(iota)
	WhiteListScanning
	WhiteListReady
)

type imageUsedItem struct {
	count          int64
	whiteListState WhiteListScannerState
}

type ConfigManager struct {
	clusterKey     string
	consoleAddr    string
	clusterMgr     *k8s.ClusterInfoManager
	lock           *sync.Mutex
	syncLock       *sync.Mutex
	policiesPtr    *atomic.Pointer[model.DaemonDriftPolicies]
	execWhiteList  map[string]map[string]string // image digest => { hash1 => exec_path,hash2 => exec_path}
	imageCountLock sync.Mutex
	imageUsedCount map[string]*imageUsedItem
	whitelistPtr   *atomic.Pointer[model.DaemonDriftWhitelist]
	client         *http.Client
}

func (cm *ConfigManager) policies() *model.DaemonDriftPolicies {
	return cm.policiesPtr.Load()
}

func (cm *ConfigManager) setPolicies(p *model.DaemonDriftPolicies) {
	cm.policiesPtr.Store(p)
}

func (cm *ConfigManager) whitelist() *model.DaemonDriftWhitelist {
	return cm.whitelistPtr.Load()
}

func (cm *ConfigManager) setWhitelist(l *model.DaemonDriftWhitelist) {
	cm.whitelistPtr.Store(l)
}

// const (
// 	internalApiKey = "dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv"
// )

// func (cm *ConfigManager) syncPolicy(ctx context.Context, ij *Injector) error {
// 	defer func() {
// 		if r := recover(); r != nil {
// 			logging.Get().Error().Str("stack", string(debug.Stack())).Msgf("panic: %v", r)
// 		}
// 	}()

// 	cm.syncLock.Lock()
// 	defer cm.syncLock.Unlock()

// 	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
// 	defer cancel()

// 	url := fmt.Sprintf("%s/api/openapi/drift/policy?cluster_key=%s&policies_version=%d&wlist_version=%d", cm.consoleAddr, cm.clusterKey, cm.policies().VersionStamp, cm.whitelist().VersionStamp)
// 	logging.Get().Info().Str("url", url).Msg("sync drift policies")

// 	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
// 	if err != nil {
// 		logging.Get().Err(err).Msgf("init requset error", url)
// 		return err
// 	}
// 	// http header
// 	req.Header.Set("X-Tensorsec-cicd-key", internalApiKey)
// 	req.Header.Set("Content-Type", "application/json")
// 	// http request
// 	resp, err := cm.client.Do(req)
// 	if err != nil {
// 		logging.Get().Error().Err(err).Msgf("request url:%v error", url)
// 		return err
// 	}
// 	defer func() {
// 		_ = resp.Body.Close()
// 	}()

// 	if resp.StatusCode != 200 {
// 		logging.Get().Err(err).Msgf("request status code error:%v", resp.StatusCode)
// 		return fmt.Errorf("rsp code err:%d", resp.StatusCode)
// 	}
// 	data, err := io.ReadAll(resp.Body)
// 	if err != nil {
// 		logging.Get().Err(err).Msgf("read scanner req body error")
// 		return err
// 	}

// 	var driftResp model.DaemonDriftResp
// 	err = json.Unmarshal(data, &driftResp)
// 	if err != nil {
// 		logging.Get().Err(err).Msgf("unmarshal policy error")
// 		return err
// 	}

// 	prevVersion := cm.policies().VersionStamp
// 	newVersion := driftResp.Data.Policies.VersionStamp

// 	logging.Get().Trace().Interface("whitelist", driftResp.Data.Whitelist).Interface("policies", driftResp.Data.Policies).Interface("policyItems", driftResp.Data.Items).Int64("new_version", newVersion).Int64("old_version", prevVersion).Msg("Try to update drift policies")

// 	if newVersion > prevVersion {
// 		policies := make(map[uint32]model.DriftPolicy, len(driftResp.Data.Items))
// 		for _, v := range driftResp.Data.Items {
// 			policies[v.ResourceUUID] = v
// 		}
// 		cm.setPolicies(&model.DaemonDriftPolicies{
// 			Policies:     policies,
// 			VersionStamp: newVersion,
// 		})
// 		logging.Get().Info().Int64("new_version", newVersion).Int64("old_version", prevVersion).Msg("Policies updated successfully")
// 	}
// 	ij.UpdateContainerDriftSwitch(cm.policies().Policies)

// 	newWhitelist := make(map[string]int64, len(driftResp.Data.Whitelist.Whitelist))
// 	nowTimestamp := time.Now().UnixMilli()
// 	var version int64
// 	if driftResp.Data.Whitelist.VersionStamp > cm.whitelist().VersionStamp {
// 		for _, v := range driftResp.Data.Whitelist.Whitelist {
// 			if nowTimestamp < v.ExpireAt {
// 				newWhitelist[v.Path] = v.ExpireAt
// 			} else if v.IsForever {
// 				newWhitelist[v.Path] = 0
// 			}
// 		}
// 	} else { // if no updates, expire items.
// 		for path, expiredAt := range cm.whitelist().Whitelist {
// 			if nowTimestamp < expiredAt || expiredAt == 0 {
// 				newWhitelist[path] = expiredAt
// 			}
// 		}
// 		logging.Get().Info().Int64("new_version", version).Int64("old_version", cm.whitelist().VersionStamp).Msg("try to expire whitelist with no updates")
// 	}

// 	version = driftResp.Data.Whitelist.VersionStamp
// 	logging.Get().Info().Int64("new_version", version).Int64("old_version", cm.whitelist().VersionStamp).Msg("try to update whitelist")

// 	oldWlistVersion := cm.whitelist().VersionStamp
// 	cm.setWhitelist(&model.DaemonDriftWhitelist{
// 		Whitelist:    newWhitelist,
// 		VersionStamp: version,
// 	})
// 	logging.Get().Info().Int64("new_version", version).Int64("old_version", oldWlistVersion).Msg("update whitelist successfully")

// 	return nil
// }

func (cm *ConfigManager) GetPolicyByResourceUUID(uuid uint32) (model.DriftPolicy, bool) {
	policy, ok := cm.policies().Policies[uuid]
	logging.Get().Info().Msgf("uuid:%v, policy:%+v", uuid, policy)

	return policy, ok
}

func (cm *ConfigManager) updateFromConfigMap(ctx context.Context, configMap *corev1.ConfigMap, ij *Injector) error {
	logging.Get().Info().Msg("update config map")

	cm.syncLock.Lock()
	defer cm.syncLock.Unlock()

	if configMap.Name == model.PoliciesConfigMapName {
		policies := make(map[uint32]model.DriftPolicy, len(configMap.Data))
		for _, v := range configMap.Data {

			values := strings.Split(v, "/")
			if len(values) != len(strings.Split(model.PolicyConfigMapValueTemplate, "/")) {
				logging.Get().Error().Msg("policy configmap value template error")
				continue
			}
			clusterKey, namespace, kind, name, enable, mode := values[0], values[1], values[2], values[3], values[4], values[5]
			// enable to int
			enableInt, err := strconv.Atoi(enable)
			if err != nil {
				logging.Get().Error().Err(err).Msgf("strconv enable:%v error", enable)
				continue
			}
			uuid := util.GenerateUUID(clusterKey, namespace, kind, name)
			policies[uuid] = model.DriftPolicy{
				ResourceUUID: uuid,
				ClusterKey:   clusterKey,
				Namespace:    namespace,
				ResourceKind: kind,
				Resource:     name,
				Enable:       enableInt,
				Mode:         mode,
			}
		}
		cm.setPolicies(&model.DaemonDriftPolicies{
			Policies:     policies,
			VersionStamp: 0,
		})
		ij.UpdateContainerDriftSwitch(cm.policies().Policies)
	} else if configMap.Name == model.WhitelistConfigMapName {
		newWhitelist := make(map[string]int64, len(configMap.Data))
		nowTimestamp := time.Now().UnixMilli()
		for _, v := range configMap.Data {
			values := strings.Split(v, ":")
			if len(values) != len(strings.Split(model.WhitelistConfigMapValueTemplate, ":")) {
				logging.Get().Error().Msg("whitelist configmap value template error")
				continue
			}
			path, expireAt, isForever := values[0], values[1], values[2]
			logging.Get().Info().Msgf("path:%v, expireAt:%v, isForever:%v", path, expireAt, isForever)
			expireAtInt, err := strconv.ParseInt(expireAt, 10, 64)
			if err != nil {
				logging.Get().Error().Err(err).Msgf("strconv expireAt:%v error", expireAt)
				continue
			}
			if nowTimestamp < expireAtInt {
				newWhitelist[path] = expireAtInt
			} else if isForever == "true" {
				newWhitelist[path] = int64(^uint64(0) >> 1)
			}
		}
		logging.Get().Info().Msgf("newWhitelist:%+v", newWhitelist)
		cm.setWhitelist(&model.DaemonDriftWhitelist{
			Whitelist:    newWhitelist,
			VersionStamp: 0,
		})
	} else {
		logging.Get().Error().Msg("unknown configmap added")
	}

	return nil
}

func (cm *ConfigManager) Start(ij *Injector) error {
	logging.Get().Info().Msg("config manager start")

	namespace := os.Getenv("MY_POD_NAMESPACE")
	if namespace == "" {
		namespace = "tensorsec"
	}

	softName := os.Getenv("SOFT_NAME")
	if softName == "" {
		softName = "tensorsec"
	}

	consoleDeploymentName := fmt.Sprintf("%s-console", softName)
	if os.Getenv("TENSORSEC_CONSOLE_DEPLOYMENT_NAME") != "" {
		consoleDeploymentName = os.Getenv("TENSORSEC_CONSOLE_DEPLOYMENT_NAME")
	}

	// Wait for the Deployment to be ready
	err := wait.PollImmediate(time.Second, 5*time.Minute, func() (bool, error) {
		deployment, err := cm.clusterMgr.HostClient.AppsV1().Deployments(namespace).Get(context.Background(), consoleDeploymentName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		return deployment.Status.ReadyReplicas > 0, nil
	})
	if err != nil {
		logging.Get().Error().Err(err).Msg("wait for console deployment error")
		return err
	}

	// Wait for the drift configmap init
	time.Sleep(5 * time.Second)

	// Start the initial timer
	outTime := time.Minute * 20
	timer := time.NewTimer(outTime)

	watcher, err := cm.clusterMgr.HostClient.CoreV1().ConfigMaps(namespace).Watch(context.Background(), metav1.ListOptions{
		// FieldSelector: "metadata.name=drift-config",
		LabelSelector: model.DriftConfigMapLabel,
	})
	if err != nil {
		logging.Get().Error().Err(err).Msg("watch configmap error")
		return err
	}

	logging.Get().Info().Str("namespace", namespace).Msg("watch configmap start")
	for {
		select {
		case event, ok := <-watcher.ResultChan():
			if !ok {
				logging.Get().Warn().Msg("Result channel closed, restarting the watch process")
				watcher.Stop()
				watcher, err = cm.clusterMgr.HostClient.CoreV1().ConfigMaps(namespace).Watch(context.Background(), metav1.ListOptions{
					LabelSelector: model.DriftConfigMapLabel,
				})
				if err != nil {
					logging.Get().Error().Err(err).Msg("watch configmap error")
				}
				timer.Reset(outTime)
				continue
			}
			switch event.Type {
			case watch.Added:
				//ConfigMap added: &ConfigMap{ObjectMeta:{drift-policies  tensorsec  17d742a7-ea1b-4108-a604-533fb280a843 95767605 0 2023-06-21 08:17:55 +0000 UTC <nil> <nil> map[app:drift-configMap] map[] [] []  [{console Update v1 2023-06-21 08:17:55 +0000 UTC FieldsV1 {"f:data":{".":{},"f:policy-16":{}},"f:metadata":{"f:labels":{".":{},"f:app":{}}}} }]},Data:map[string]string{policy-16: 494c5054-4b9b-4944-8452-84b8893c21b7/del/Deployment/test/0/alert,},BinaryData:map[string][]byte{},Immutable:nil,}
				configMap := event.Object.(*corev1.ConfigMap)
				logging.Get().Info().Msgf("ConfigMap added: %v\n", configMap.Data)
				err = cm.updateFromConfigMap(context.Background(), configMap, ij)
				if err != nil {
					logging.Get().Error().Err(err).Msg("update from configmap error")
				}
			case watch.Modified:
				configMap := event.Object.(*corev1.ConfigMap)
				logging.Get().Info().Msgf("ConfigMap updated: %+v\n", configMap)
				err = cm.updateFromConfigMap(context.Background(), configMap, ij)
				if err != nil {
					logging.Get().Error().Err(err).Msg("update from configmap error")
				}
			case watch.Deleted:
				configMap := event.Object.(*corev1.ConfigMap)
				logging.Get().Info().Msgf("ConfigMap deleted: %+v\n", configMap)
			case watch.Error:
				configMap := event.Object.(*corev1.ConfigMap)
				logging.Get().Error().Msgf("ConfigMap error: %+v\n", configMap)
			}
		case <-timer.C:
			logging.Get().Warn().Msg("Timeout reached, restarting the watch process")
			watcher.Stop()
			watcher, err = cm.clusterMgr.HostClient.CoreV1().ConfigMaps(namespace).Watch(context.Background(), metav1.ListOptions{
				LabelSelector: model.DriftConfigMapLabel,
			})
			if err != nil {
				logging.Get().Error().Err(err).Msg("watch configmap error")
			}
		}

	}
	return nil
}

func (cm *ConfigManager) IsImageDigestsExist(imageDigests []string) (string, bool) {
	for _, v := range imageDigests {
		if cm.isImageDigestExist(v) {
			return v, true
		}
	}
	return "", false
}

func (cm *ConfigManager) isImageDigestExist(imageDigest string) bool {
	cm.lock.Lock()
	defer cm.lock.Unlock()
	_, ok := cm.execWhiteList[imageDigest]
	return ok
}

func (cm *ConfigManager) IsInWhiteList(imageDigest, filePath string) (notInWhitelist bool, expected string) {
	cm.lock.Lock()
	defer cm.lock.Unlock()
	_, ok := cm.execWhiteList[imageDigest]
	logging.Get().Debug().Msgf("imageDigest:%v, filePath:%v, whitelist generated:%v", imageDigest, filePath, ok)
	notInWhitelist = !ok
	if ok {
		_, ok1 := cm.execWhiteList[imageDigest][filePath]
		if ok1 {
			return false, cm.execWhiteList[imageDigest][filePath]
		} else {
			notInWhitelist = true
			expected = ""
		}
	}
	return notInWhitelist, expected
}

func (cm *ConfigManager) WhiteListSize() int {
	return len(cm.execWhiteList)
}

func (cm *ConfigManager) ImageExecHashSize(imageDigest string) int {
	_, ok := cm.execWhiteList[imageDigest]
	if ok {
		return len(cm.execWhiteList[imageDigest])
	}
	return -1
}

func (cm *ConfigManager) SetImageExecHash(imageDigest, hash, execPath string) {
	cm.lock.Lock()
	defer cm.lock.Unlock()
	_, ok := cm.execWhiteList[imageDigest]
	if !ok {
		execHash := make(map[string]string)
		cm.execWhiteList[imageDigest] = execHash
	}
	cm.execWhiteList[imageDigest][hash] = execPath
}

func (cm *ConfigManager) MockWhiteListFromFile(imageDigestFile, hashFile string) error {
	// load hash file
	hf, err := os.OpenFile(hashFile, os.O_RDWR, 0666)
	if err != nil {
		return fmt.Errorf("open file err:%v", err)
	}
	defer func() {
		_ = hf.Close()
	}()

	hashList := make(map[string]string)
	buf := bufio.NewReader(hf)
	for {
		line, err := buf.ReadString('\n')
		line = strings.TrimSpace(line)
		if err != nil {
			if err == io.EOF {
				logging.Get().Debug().Msg("hash file read end")
				break
			} else {
				return fmt.Errorf("read file err:%v", err)
			}
		}
		arr := strings.Split(line, " ")
		if len(arr) != 2 {
			logging.Get().Debug().Msgf("wrong format:%s", line)
			continue
		}
		hashList[arr[1]] = arr[0]
	}

	// load image digest file
	df, err := os.OpenFile(imageDigestFile, os.O_RDWR, 0666)
	if err != nil {
		return fmt.Errorf("open file err:%v", err)
	}
	defer df.Close()

	buf2 := bufio.NewReader(df)
	for {
		line, err := buf2.ReadString('\n')
		line = strings.TrimSpace(line)
		if err != nil {
			if err == io.EOF {
				logging.Get().Debug().Msg("read file end")
				break
			} else {
				return fmt.Errorf("read file err:%v", err)
			}
		}
		cm.lock.Lock()
		cm.execWhiteList[line] = hashList
		cm.lock.Unlock()
	}

	return nil
}

func (cm *ConfigManager) SetContainerWhiteList(imageDigest string, whiteList []whitelist.WhitelistFile) {
	cm.lock.Lock()
	defer cm.lock.Unlock()

	if len(whiteList) == 0 {
		logging.Get().Debug().Msgf("imageDigest:%v, whitelist is empty", imageDigest)
		return
	}

	if cm.execWhiteList[imageDigest] == nil {
		cm.execWhiteList[imageDigest] = make(map[string]string)
	} else {
		logging.Get().Trace().Msgf("image whitelist exist imageDigest:%v, whiteList:%v\n", imageDigest, whiteList)
		return
	}

	for _, file := range whiteList {
		cm.execWhiteList[imageDigest][file.Name] = file.Checksum
	}
}

func (cm *ConfigManager) deleteWhiteListByImageDigest(imageDigest string) {
	cm.lock.Lock()
	defer cm.lock.Unlock()
	delete(cm.execWhiteList, imageDigest)
}

func (cm *ConfigManager) AddImageUsed(imageDigest string) {
	cm.imageCountLock.Lock()
	defer cm.imageCountLock.Unlock()

	if cm.imageUsedCount == nil {
		cm.imageUsedCount = make(map[string]*imageUsedItem)
	}
	logging.Get().Debug().Msgf("imageDigest:%v, item:%v", imageDigest, cm.imageUsedCount[imageDigest])
	// cm.imageUsedCount[imageDigest]++
	if _, ok := cm.imageUsedCount[imageDigest]; !ok {
		cm.imageUsedCount[imageDigest] = &imageUsedItem{
			count:          0,
			whiteListState: WhiteListNotReady,
		}
	}
	cm.imageUsedCount[imageDigest].count++
}

func (cm *ConfigManager) DelImageUsedAndTestWhiteList(imageDigest string) {
	cm.imageCountLock.Lock()
	defer cm.imageCountLock.Unlock()
	cm.imageUsedCount[imageDigest].count--
	if cm.imageUsedCount[imageDigest].count == 0 {
		logging.Get().Trace().Msgf("delete %v from map", imageDigest)

		cm.deleteWhiteListByImageDigest(imageDigest)
	} else if cm.imageUsedCount[imageDigest].count < 0 {
		logging.Get().Error().Msgf("imageDigest:%v, imageUsedCount:%v", imageDigest, cm.imageUsedCount[imageDigest])
		cm.imageUsedCount[imageDigest].count = 0

	}
}

func (cm *ConfigManager) SetWhiteListNotReady(imageDigest string) error {
	cm.imageCountLock.Lock()
	defer cm.imageCountLock.Unlock()

	if _, ok := cm.imageUsedCount[imageDigest]; !ok {
		return errors.New("imageDigest not exist ")
	}

	cm.imageUsedCount[imageDigest].whiteListState = WhiteListNotReady
	return nil
}

func (cm *ConfigManager) SetWhiteListScanning(imageDigest string) error {
	cm.imageCountLock.Lock()
	defer cm.imageCountLock.Unlock()

	if _, ok := cm.imageUsedCount[imageDigest]; !ok {
		return errors.New("imageDigest not exist ")
	}
	cm.imageUsedCount[imageDigest].whiteListState = WhiteListScanning
	return nil
}

func (cm *ConfigManager) SetWhiteListReady(imageDigest string) error {
	cm.imageCountLock.Lock()
	defer cm.imageCountLock.Unlock()
	if _, ok := cm.imageUsedCount[imageDigest]; !ok {
		return errors.New("imageDigest not exist ")
	}
	cm.imageUsedCount[imageDigest].whiteListState = WhiteListReady
	return nil

}

func (cm *ConfigManager) GetWhiteListState(imageDigest string) (WhiteListScannerState, bool) {
	cm.imageCountLock.Lock()
	defer cm.imageCountLock.Unlock()
	if _, ok := cm.imageUsedCount[imageDigest]; !ok {
		return WhiteListNotReady, ok
	}
	return cm.imageUsedCount[imageDigest].whiteListState, true
}

func (cm *ConfigManager) IsInGlobalWhitelist(path string) bool {
	expiredAt, ok := cm.whitelist().Whitelist[path]
	if !ok {
		return false
	}
	return time.Now().UnixMilli() <= expiredAt
}

func NewConfigManger(consoleAddr, clusterKey string, clusterManager *k8s.ClusterInfoManager) (*ConfigManager, error) {
	cm := &ConfigManager{
		clusterKey:   clusterKey,
		consoleAddr:  consoleAddr,
		clusterMgr:   clusterManager,
		policiesPtr:  new(atomic.Pointer[model.DaemonDriftPolicies]),
		whitelistPtr: new(atomic.Pointer[model.DaemonDriftWhitelist]),
		lock:         new(sync.Mutex),
		syncLock:     new(sync.Mutex),
	}

	// http transport
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	// http client
	cm.client = &http.Client{Transport: tr}
	cm.execWhiteList = make(map[string]map[string]string)
	cm.imageUsedCount = make(map[string]*imageUsedItem)
	cm.setWhitelist(&model.DaemonDriftWhitelist{
		Whitelist:    make(map[string]int64, 0),
		VersionStamp: 0,
	})
	cm.setPolicies(&model.DaemonDriftPolicies{
		Policies:     make(map[uint32]model.DriftPolicy, 0),
		VersionStamp: 0,
	})
	return cm, nil
}
