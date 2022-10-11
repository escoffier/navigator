package dp

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	json "github.com/json-iterator/go"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/dp/whitelist"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/logging"
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

const (
	internalApiKey = "dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv"
)

func (cm *ConfigManager) syncPolicy(ctx context.Context) error {
	defer func() {
		if r := recover(); r != nil {
			logging.Get().Error().Str("stack", string(debug.Stack())).Msgf("panic: %v", r)
		}
	}()

	cm.syncLock.Lock()
	defer cm.syncLock.Unlock()

	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	url := fmt.Sprintf("%s/api/openapi/drift/policy?cluster_key=%s&policies_version=%d&wlist_version=%d", cm.consoleAddr, cm.clusterKey, cm.policies().VersionStamp, cm.whitelist().VersionStamp)
	logging.Get().Info().Str("url", url).Msg("sync drift policies")

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		logging.Get().Err(err).Msgf("init requset error", url)
		return err
	}
	//http header
	req.Header.Set("X-Tensorsec-cicd-key", internalApiKey)
	req.Header.Set("Content-Type", "application/json")
	//http request
	resp, err := cm.client.Do(req)
	if err != nil {
		logging.Get().Error().Err(err).Msgf("request url:%v error", url)
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != 200 {
		logging.Get().Err(err).Msgf("request status code error:%v", resp.StatusCode)
		return fmt.Errorf("rsp code err:%d", resp.StatusCode)
	}
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logging.Get().Err(err).Msgf("read scanner req body error")
		return err
	}
	logging.Get().Debug().Msg(string(data))

	var driftResp model.DaemonDriftResp
	err = json.Unmarshal(data, &driftResp)
	if err != nil {
		logging.Get().Err(err).Msgf("unmarshal policy error")
		return err
	}

	logging.Get().Trace().Interface("whitelist", driftResp.Data.Whitelist).Interface("policies", driftResp.Data.Policies).Interface("policyItems", driftResp.Data.Items).Msg("sync policy success")

	if cm.policies().VersionStamp == 0 || len(driftResp.Data.Items) > 0 {
		policies := make(map[uint32]model.DriftPolicy, len(driftResp.Data.Items))
		for _, v := range driftResp.Data.Items {
			policies[v.ResourceUUID] = v
		}
		prevVersion := cm.policies().VersionStamp
		cm.setPolicies(&model.DaemonDriftPolicies{
			Policies:     policies,
			VersionStamp: driftResp.Data.Policies.VersionStamp,
		})
		logging.Get().Info().Int64("new_version", driftResp.Data.Policies.VersionStamp).Int64("old_version", prevVersion).Msg("Policies updated successfully")
	}

	newWhitelist := make(map[string]int64, len(driftResp.Data.Whitelist.Whitelist))
	nowTimestamp := time.Now().UnixMilli()
	var version int64
	if cm.whitelist().VersionStamp == 0 || len(driftResp.Data.Whitelist.Whitelist) > 0 { // update
		for _, v := range driftResp.Data.Whitelist.Whitelist {
			if nowTimestamp < v.ExpireAt {
				newWhitelist[v.Path] = v.ExpireAt
			} else if v.IsForever {
				newWhitelist[v.Path] = 0
			}
		}
		version = driftResp.Data.Whitelist.VersionStamp
		logging.Get().Info().Int64("new_version", version).Int64("old_version", cm.whitelist().VersionStamp).Msg("try to update whitelist")
	} else { // clear items of expired
		version = cm.whitelist().VersionStamp
		for path, expiredAt := range cm.whitelist().Whitelist {
			if nowTimestamp < expiredAt || expiredAt == 0 {
				newWhitelist[path] = expiredAt
			}
		}
		logging.Get().Info().Int64("new_version", version).Int64("old_version", cm.whitelist().VersionStamp).Msg("try to expire whitelist with no updates")
	}

	oldWlistVersion := cm.whitelist().VersionStamp
	cm.setWhitelist(&model.DaemonDriftWhitelist{
		Whitelist:    newWhitelist,
		VersionStamp: version,
	})
	logging.Get().Info().Int64("new_version", version).Int64("old_version", oldWlistVersion).Msg("update whitelist successfully")

	return nil
}

func (cm *ConfigManager) GetPolicyByResourceUUID(uuid uint32) (model.DriftPolicy, bool) {
	policy, ok := cm.policies().Policies[uuid]
	logging.Get().Info().Msgf("uuid:%v, policy:%+v", uuid, policy)

	return policy, ok
}

func (cm *ConfigManager) Start() error {
	logging.Get().Info().Msg("config manager start")

	for {
		err := cm.syncPolicy(context.Background())
		if err != nil {
			logging.Get().Error().Err(err).Msgf("SyncPolicy error")
			time.Sleep(time.Second * 20)
			continue
		}
		defaultTime := 10
		intervalTime := int64(defaultTime) + rand.Int63n(6)
		time.Sleep(time.Second * time.Duration(intervalTime))
	}
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
	logging.Get().Debug().Msgf("imageDigest:%v, filePath:%v, ok:%v", imageDigest, filePath, ok)
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
	cm.imageCountLock.Unlock()
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
	return expiredAt == 0 || time.Now().UnixMilli() <= expiredAt
}

func NewConfigManger(consoleAddr, clusterKey string) (*ConfigManager, error) {
	cm := &ConfigManager{
		clusterKey:   clusterKey,
		consoleAddr:  consoleAddr,
		policiesPtr:  new(atomic.Pointer[model.DaemonDriftPolicies]),
		whitelistPtr: new(atomic.Pointer[model.DaemonDriftWhitelist]),
		lock:         new(sync.Mutex),
		syncLock:     new(sync.Mutex),
	}

	//http transport
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	//http client
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
