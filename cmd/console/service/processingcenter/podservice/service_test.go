package podservice

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConcatMicroSegURL(t *testing.T) {
	servie := &Service{
		microSegBaseURL: "http://tensorsec-microseg:8090",
	}
	url, err := servie.getRequestURL(IsolatePath)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "http://tensorsec-microseg:8090/api/v2/microseg/isolate", url)
}

func TestMarshal(t *testing.T) {
	var jsonBytes = []byte(`{
  "apiVersion": "v2",
  "data": {
    "failedPods": [
      {
        "cluster": "string",
        "errMsg": "string",
        "name": "string",
        "namespace": "string"
      }
    ],
    "lostPods": [
      {
        "cluster": "string",
        "name": "string",
        "namespace": "string"
      }
    ],
    "passedPods": [
      {
        "cluster": "string",
        "name": "string",
        "namespace": "string"
      }
    ]
  }
}`)
	var rsp *PodOpRsp
	var err = json.Unmarshal(jsonBytes, &rsp)
	if err != nil {
		t.Fatal(err)
	}
	for _, pod := range rsp.Data.PassedPods {
		t.Log(pod)
	}
}

func TestIsPodNotFoundErr(t *testing.T) {
	err1 := errors.New("pods xxs not found")
	err2 := errors.New("pods what ever")
	assert.Equal(t, true, isPodNotFoundErr(err1))
	assert.Equal(t, false, isPodNotFoundErr(err2))
}
