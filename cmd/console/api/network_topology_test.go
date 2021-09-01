package api

import (
	"encoding/json"
	"testing"
	"time"
)

func Test_MarshalRequest(t *testing.T) {
	req := request{
		UUID:   123,
		Time:   time.Now().Unix(),
		Status: 0,
	}

	bytes, err := json.Marshal(&req)
	if err != nil {
		t.Log(err)
		return
	}
	t.Log(string(bytes))

}

func Test_unMarshalRequest(t *testing.T) {

	var data1 = []byte(`
{"time": 1630480774,"status":0}
`)

	var req request
	err := json.Unmarshal(data1, &req)
	if err != nil {
		t.Log(err)
		return
	}
	t.Logf("%+v", req)

}
