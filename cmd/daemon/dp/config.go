package dp

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/dp/checksum"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/logging"
)

type ConfigManager struct {
	consoleAddr    string
	lock           sync.Mutex
	policylock     sync.Mutex
	policys        model.DaemonDriftPolicys
	execWhiteList  map[string]map[string]string // image digest => { hash1 => exec_path,hash2 => exec_path}
	imageCountLock sync.Mutex
	imageUsedCount map[string]int64
}

func (cm *ConfigManager) queryAndFillMap(ctx context.Context) error {
	url := fmt.Sprintf("%s/api/openapi/drift/policy?last_time=%d", cm.consoleAddr, cm.policys.LastTime)
	logging.Get().Debug().Msgf("url is %v ", url)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	cli := http.Client{Transport: tr, Timeout: 60 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	req.Header.Add("X-Tensorsec-cicd-key", "dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv")
	req.Header.Add("Content-Type", "application/json")
	if err != nil {
		logging.Get().Error().Err(err).Msgf("init requset error", url)
		return err
	}
	resp, err := cli.Do(req)
	if err != nil {
		logging.Get().Error().Err(err).Msgf("requset url:%v error", url)
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		logging.Get().Error().Err(err).Msgf("request statuscode error:%v", resp.StatusCode)
	}
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logging.Get().Error().Err(err).Msgf("read scanner req body error")
		return err
	}
	logging.Get().Info().Msgf("resp body is ", string(data))
	var policys model.DaemonDriftResp
	err = json.Unmarshal(data, &policys)
	if err != nil {
		logging.Get().Error().Err(err).Msgf("unmarshal policys error")
		return err
	}

	if policys.Data.TotalItems == -1 {
		return nil
	}

	logging.Get().Info().Msgf("policys is %v", policys.Data.Items)
	cm.policylock.Lock()
	cm.policys.Policys = make(map[uint32]model.DriftPolicy)
	var maxTime int64
	for _, v := range policys.Data.Items {
		if maxTime < v.UpdatedAt.Unix() {
			maxTime = v.UpdatedAt.Unix()
		}
		cm.policys.Policys[v.ResourceUUID] = v
	}

	cm.policylock.Unlock()
	return nil
}

func (cm *ConfigManager) GetPloicyByResourceUUID(uuid uint32) (model.DriftPolicy, bool) {
	cm.policylock.Lock()
	defer cm.policylock.Unlock()
	policy, ok := cm.policys.Policys[uuid]
	logging.Get().Info().Msgf("uuid:%v, policy:%+v", uuid, policy)

	return policy, ok
}

func (cm *ConfigManager) Start() error {
	logging.Get().Info().Msg("config manager start")
	for {
		// get white list by api
		// if cm.execWhiteList == nil {
		// 	cm.execWhiteList = make(map[string]map[string]string)
		// }
		// // write to Exec white list,
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*60)
		err := cm.queryAndFillMap(ctx)
		cancel()
		if err != nil {
			logging.Get().Error().Err(err).Msgf("queryAndFillMap error")
			time.Sleep(time.Second * 20)
			return err
		}
		time.Sleep(time.Minute * 1)
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
	defer hf.Close()

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

func (cm *ConfigManager) SetContainerWhiteList(imageDigest string, whiteList []checksum.WhitelistFile) {
	cm.lock.Lock()
	defer cm.lock.Unlock()

	if len(whiteList) == 0 {
		logging.Get().Debug().Msgf("imageDigest:%v, whitelist is empty", imageDigest)
		return
	}

	if cm.execWhiteList[imageDigest] == nil {
		cm.execWhiteList[imageDigest] = make(map[string]string)
	} else {
		logging.Get().Error().Msgf("image whitelist exist imageDigest:%v, whiteList:%v\n", imageDigest, whiteList)
		return
	}

	for _, file := range whiteList {
		cm.execWhiteList[imageDigest][file.Name] = file.Checksum
	}
}

func (cm *ConfigManager) AddImageUsed(imageDigest string) {
	cm.imageCountLock.Lock()
	defer cm.imageCountLock.Unlock()
	if cm.imageUsedCount == nil {
		cm.imageUsedCount = make(map[string]int64)
	}
	cm.imageUsedCount[imageDigest]++
}

func (cm *ConfigManager) DelImageUsedAndTestWhiteList(imageDigest string) {
	cm.imageCountLock.Lock()
	defer cm.imageCountLock.Unlock()
	cm.imageUsedCount[imageDigest]--
	if cm.imageUsedCount[imageDigest] == 0 {
		logging.Get().Info().Msgf("delete %v from map", imageDigest)
		cm.lock.Lock()
		delete(cm.execWhiteList, imageDigest)
		cm.lock.Unlock()
	} else if cm.imageUsedCount[imageDigest] < 0 {
		logging.Get().Error().Msgf("imageDigest:%v, imageUsedCount:%v", imageDigest, cm.imageUsedCount[imageDigest])
		cm.imageUsedCount[imageDigest] = 0

	}
}

func NewConfigManger() (*ConfigManager, error) {
	cm := &ConfigManager{}
	cm.execWhiteList = make(map[string]map[string]string)
	cm.imageUsedCount = make(map[string]int64)
	cm.policys = model.DaemonDriftPolicys{
		Policys:  make(map[uint32]model.DriftPolicy),
		LastTime: 0,
	}
	return cm, nil
}
