package engine

import (
	"errors"
	"testing"
	"time"

	_ "gitlab.com/piccolo_su/vegeta/test/cmd/scanner/component/jobs/mock-pull-image"
	_ "gitlab.com/piccolo_su/vegeta/test/cmd/scanner/component/jobs/mock-scan"
	_ "gitlab.com/piccolo_su/vegeta/test/cmd/scanner/component/mock-db-dequeue"
	_ "gitlab.com/piccolo_su/vegeta/test/cmd/scanner/component/mock-dequeue"
	_ "gitlab.com/piccolo_su/vegeta/test/cmd/scanner/component/mock-flow-conf"
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

func TestEngine(t *testing.T) {
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
