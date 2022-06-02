package engine

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/logging"
)

var counter = 0

func loopOnce(param interface{}) error {

	if counter >= 1 {
		time.Sleep(time.Duration(30) * time.Second)
		return errors.New("loop once end")
	}
	counter = counter + 1

	return nil
}

var execWhiteList map[string]map[string]string

func queryAndFillMap(consoleAddr string) error {
	// url := fmt.Sprintf("%s/api/openapi/scanner/images/bin/whitelist", consoleAddr)
	// cli := http.Client{}
	// req, err := http.NewRequest("GET", url, nil)
	// req.Header.Add("X-Tensorsec-cicd-key", "dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv")
	// req.Header.Add("Content-Type", "application/json")
	// if err != nil {
	// 	logging.Get().Error().Err(err).Msgf("init requset error", url)
	// 	return err
	// }
	// resp, err := cli.Do(req)
	// if err != nil {
	// 	logging.Get().Error().Err(err).Msgf("requset url:%v error", url)
	// 	return err
	// }
	// defer resp.Body.Close()
	// data, err := ioutil.ReadAll(resp.Body)
	// if err != nil {
	// 	logging.Get().Error().Err(err).Msgf("read scanner req body error")
	// 	return err
	// }
	var whitelist model.DaemonDriftResp
	err := json.Unmarshal([]byte(`{"apiVersion":"1.0","data":{"totalItems":8,"items":[{"created_at":"2022-05-24T02:38:53.117Z","creator":"yangzhirong@tensorsecurity.cn","enable":1,"resource":"curl-sit","cluster_key":"c35d049a-ea07-4107-8ad9-a95adce38413","updator":"","id":6,"updated_at":"2022-05-26T13:49:00.312Z","resource_uuid":1367883406,"resource_type":"Pod","namespace":"default","mode":2},{"resource_uuid":141769365,"resource_type":"Pod","resource":"host-bench-pod","cluster_key":"e886669a-96c8-426a-be5d-f9018e8f2b5f","updator":"","mode":2,"id":12,"updated_at":"2022-05-25T09:37:34.154Z","namespace":"default","creator":"yangzhirong@tensorsecurity.cn","enable":0,"created_at":"2022-05-25T09:37:25.057Z"},{"mode":1,"id":13,"updated_at":"2022-05-25T09:38:32.516Z","resource":"faulty","updator":"","cluster_key":"e886669a-96c8-426a-be5d-f9018e8f2b5f","creator":"yangzhirong@tensorsecurity.cn","enable":1,"created_at":"2022-05-25T09:38:32.516Z","resource_uuid":1409446597,"resource_type":"Deployment","namespace":"default"},{"resource_uuid":1409446597,"resource_type":"Deployment","resource":"faulty","creator":"guolingkai@tensorsecurity.cn","enable":0,"mode":1,"id":14,"created_at":"2022-05-25T09:52:49.633Z","cluster_key":"e886669a-96c8-426a-be5d-f9018e8f2b5f","updator":"","updated_at":"2022-05-25T09:52:49.633Z","namespace":"default"},{"id":15,"resource_uuid":1213872407,"resource_type":"Deployment","resource":"wade-test-deployment","cluster_key":"e886669a-96c8-426a-be5d-f9018e8f2b5f","creator":"lingximo@tensorsecurity.cn","created_at":"2022-05-25T11:31:41.56Z","updated_at":"2022-05-25T11:31:41.56Z","namespace":"wade-test","updator":"","enable":1,"mode":2},{"id":16,"updated_at":"2022-05-26T14:50:34.957Z","namespace":"default","creator":"u1@163.com","enable":1,"created_at":"2022-05-26T14:50:34.957Z","resource_uuid":1409446597,"resource_type":"Deployment","resource":"faulty","cluster_key":"e886669a-96c8-426a-be5d-f9018e8f2b5f","updator":"","mode":1},{"creator":"u1@163.com","enable":0,"mode":1,"id":17,"resource":"wade-test-deployment","resource_uuid":1213872407,"resource_type":"Deployment","namespace":"wade-test","cluster_key":"e886669a-96c8-426a-be5d-f9018e8f2b5f","updator":"","created_at":"2022-05-26T14:51:11.688Z","updated_at":"2022-05-26T14:51:11.688Z"},{"namespace":"default","resource":"faulty","creator":"u1@163.com","updator":"","enable":1,"resource_type":"Deployment","created_at":"2022-05-26T14:52:05.646Z","updated_at":"2022-05-26T14:52:05.646Z","resource_uuid":1409446597,"cluster_key":"e886669a-96c8-426a-be5d-f9018e8f2b5f","mode":2,"id":18}],"itemsPerPage":0,"startIndex":0,"status":0},"target":{"Name":"","ID":"","Link":""}}`), &whitelist)
	if err != nil {
		logging.Get().Error().Err(err).Msgf("unmarshal whitelists error")
		return err
	}

	// for k := range whitelist {
	// 	err := json.Unmarshal(whitelist[k].WhitelistJSON, &whitelist[k].Whitelists)
	// 	if err != nil {
	// 		logging.Get().Error().Err(err).Msgf("unmarshal whitelist error json:%s", whitelist[k].WhitelistJSON)
	// 		continue
	// 	}
	// }
	// execWhiteList = make(map[string]map[string]string)

	// for k, v := range whitelist {
	// 	logging.Get().Info().Msgf("sync digest :%v file:%v", v.Digest, v.Whitelists)
	// 	if len(whitelist[k].Whitelists) > 0 {
	// 		execWhiteList[v.Digest] = make(map[string]string)
	// 	}
	// 	for _, file := range whitelist[k].Whitelists {
	// 		execWhiteList[v.Digest][file.Name] = file.Checksum
	// 	}
	// }

	return nil
}
func TestEngine(t *testing.T) {
	queryAndFillMap("")
	// flag := flag.NewDefaultScannerOpts()
	// flag.RedisEndpoint = "192.168.134.26:26379,192.168.134.26:26379,192.168.134.26:26379"
	// flag.RedisPassword = "123456"
	// s, err := service.NewScanner(flag)
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// go s.Run()
	// // init db
	// err = store.InitDb()
	// if err != nil {
	// 	t.Fatalf("init db err:%v", err)
	// }

	// config := engine.SeqEngineConfig{
	// 	DeqType:       "mock-db-dequeue",
	// 	MaxTaskNum:    1,
	// 	MaxSubTaskNum: 2,
	// 	Interval:      3,
	// }

	// flowEngine := engine.NewSequenceEngine(config, loopOnce)
	// time.Sleep(time.Second * time.Duration(30))
	// flowEngine.Run(context.Background())
	// t.Log("end")
}
