package dp

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/dp/whitelist"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/logging"
)

type ConfigManager struct {
	consoleAddr    string
	lock           *sync.Mutex
	policyLock     *sync.Mutex
	policies       model.DaemonDriftPolicies
	execWhiteList  map[string]map[string]string // image digest => { hash1 => exec_path,hash2 => exec_path}
	imageCountLock sync.Mutex
	imageUsedCount map[string]int64
}

const (
	internalApiKey = "dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv"
)

func (cm *ConfigManager) SyncPolicy(ctx context.Context) error {
	url := fmt.Sprintf("%s/api/openapi/drift/policy?last_time=%d", cm.consoleAddr, cm.policies.LastTime)
	logging.Get().Debug().Msgf("url is %v ", url)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	cli := http.Client{Transport: tr, Timeout: 60 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	req.Header.Add("X-Tensorsec-cicd-key", internalApiKey)
	req.Header.Add("Content-Type", "application/json")
	if err != nil {
		logging.Get().Err(err).Msgf("init requset error", url)
		return err
	}
	resp, err := cli.Do(req)
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

	var policies model.DaemonDriftResp
	err = json.Unmarshal(data, &policies)
	if err != nil {
		logging.Get().Err(err).Msgf("unmarshal policy error")
		return err
	}

	logging.Get().Trace().Interface("policyItems", policies.Data.Items).Msg("sync policy success")

	cm.policyLock.Lock()
	cm.policies.Policies = make(map[uint32]model.DriftPolicy)
	for _, v := range policies.Data.Items {
		cm.policies.Policies[v.ResourceUUID] = v
	}
	cm.policyLock.Unlock()

	return nil
}

func (cm *ConfigManager) GetPolicyByResourceUUID(uuid uint32) (model.DriftPolicy, bool) {
	cm.policyLock.Lock()
	defer cm.policyLock.Unlock()
	policy, ok := cm.policies.Policies[uuid]
	logging.Get().Info().Msgf("uuid:%v, policy:%+v", uuid, policy)

	return policy, ok
}

func (cm *ConfigManager) Start() error {
	logging.Get().Info().Msg("config manager start")
	for {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*60)
		err := cm.SyncPolicy(ctx)
		cancel()
		if err != nil {
			logging.Get().Error().Err(err).Msgf("SyncPolicy error")
			time.Sleep(time.Second * 20)
			continue
		}
		defaultTime := 10
		intervalTime := int64(defaultTime) + rand.New(rand.NewSource(time.Now().Unix())).Int63n(6)
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
		cm.imageUsedCount = make(map[string]int64)
	}
	logging.Get().Debug().Msgf("imageDigest:%v, count:%v", imageDigest, cm.imageUsedCount[imageDigest])
	cm.imageUsedCount[imageDigest]++
}

func (cm *ConfigManager) DelImageUsedAndTestWhiteList(imageDigest string) {
	cm.imageCountLock.Lock()
	defer cm.imageCountLock.Unlock()
	cm.imageUsedCount[imageDigest]--
	if cm.imageUsedCount[imageDigest] == 0 {
		logging.Get().Trace().Msgf("delete %v from map", imageDigest)

		cm.deleteWhiteListByImageDigest(imageDigest)
	} else if cm.imageUsedCount[imageDigest] < 0 {
		logging.Get().Error().Msgf("imageDigest:%v, imageUsedCount:%v", imageDigest, cm.imageUsedCount[imageDigest])
		cm.imageUsedCount[imageDigest] = 0

	}
}

func NewConfigManger(consoleAddr string) (*ConfigManager, error) {
	cm := &ConfigManager{
		lock:        &sync.Mutex{},
		policyLock:  &sync.Mutex{},
		consoleAddr: consoleAddr,
	}
	cm.execWhiteList = make(map[string]map[string]string)
	cm.imageUsedCount = make(map[string]int64)
	cm.policies = model.DaemonDriftPolicies{
		Policies: make(map[uint32]model.DriftPolicy),
		LastTime: 0,
	}
	return cm, nil
}
