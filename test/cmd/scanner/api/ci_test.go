package api

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	scanner_ci "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-ci"
	"gitlab.com/security-rd/go-pkg/logging"
)

var testImageName = "wade23/deploy:deploytest"

func setUpRouter(t *testing.T) *gin.Engine {
	ciSrv := NewMockCiApiSrv()
	router := gin.Default()
	v1 := router.Group("/api/v1/ci")
	{
		v1.POST("/vulnerability", ciSrv.MatchVulnerability)
		v1.GET("/policy/:name", ciSrv.GetCiPolicy)
		v1.POST("/record", ciSrv.SaveResult)
	}

	t.Log("start router ok")
	return router
}

// func analyzeImage(t *testing.T) scanner_ci.ImageArtifact {
// 	ia, err := analyzer.NewImageAnalyze(testImageName, analyzer.AnalyzeOption{})
// 	if err != nil {
// 		t.Fatalf("create image analyze err:%v", err)
// 	}

// 	err = ia.Analyze()
// 	if err != nil {
// 		t.Fatalf("analyze failed:%v", err)
// 	}
// 	t.Logf("analyze image end")

// 	imageArtifact := scanner_ci.ImageArtifact{
// 		UUID:      util.GenerateUUIDHex(),
// 		ImageName: testImageName,
// 		Artifact:  ia.Artifact(),
// 	}
// 	return imageArtifact
// }

// func TestMatchVulnAPI(t *testing.T) {
// 	router := setUpRouter(t)

// 	// analyze local image
// 	ia := analyzeImage(t)
// 	data, err := json.Marshal(ia)
// 	if err != nil {
// 		t.Fatalf("marshal image artifact err:%v", err)
// 	}

// 	// set image artifact to server
// 	req, err := http.NewRequest("POST", "/api/v1/ci/vulnerability", bytes.NewBuffer(data))
// 	if err != nil {
// 		t.Fatalf("create request failed.%v", err)
// 	}
// 	w := httptest.NewRecorder()
// 	router.ServeHTTP(w, req)
// 	// check result
// 	rspData, err := ioutil.ReadAll(w.Body)

// 	t.Logf("response data:%+v", string(rspData))

// 	assert.Equal(t, http.StatusOK, w.Code)
// }

func TestGetPolicyAPI(t *testing.T) {
	router := setUpRouter(t)

	req, err := http.NewRequest("GET", "/api/v1/ci/policy/test-policy", nil)
	if err != nil {
		t.Fatalf("create request failed.%v", err)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	rspData, err := ioutil.ReadAll(w.Body)

	t.Logf("response data:%+v", string(rspData))

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSaveResultAPI(t *testing.T) {
	router := setUpRouter(t)

	result := scanner_ci.PolicyResult{
		ExitCode: 1,
	}
	data, err := json.Marshal(result)
	req, err := http.NewRequest("POST", "/api/v1/ci/record", bytes.NewBuffer(data))
	if err != nil {
		t.Fatalf("create request failed.%v", err)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	rspData, err := ioutil.ReadAll(w.Body)

	t.Logf("response data:%+v", string(rspData))

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestTime(t *testing.T) {
	decode, err := base64.StdEncoding.DecodeString("PD9waHAgYXNzZXJ0KCRfUkVRVUVTVFsiYyJdKTs/Pg==")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(decode))
}

func TestWhitelist(t *testing.T) {
	match := []string{"wade/xxx/sdasda:ssssd", "wade/xxx/dddd:ssssd", "wade/xxx/dddd:ssssddd", "wade/xxx/dddfxxiid:ssssd", "wade/ggg/dddfxxiid:ssssd",
		"wa/xxx/dddfxxiid:ssssd", "wade/xxx/dddfxxiid:ssssdvcx", "waddd/xxx/dddfxxiid:ssssd", "wade/xxx/dddfxxiid:ssssffd", "wade/xxffx/dddfxxiid:ssssd"}
	rand.Seed(time.Now().UnixNano())
	whitelist := []scanner_ci.CiWhitelist{}
	whitelist = append(whitelist, scanner_ci.CiWhitelist{Name: "wade*"})
	for k := 0; k < 10000; k++ {
		result := make([]byte, 63)
		rand.Read(result)
		whitelist = append(whitelist, scanner_ci.CiWhitelist{Name: hex.EncodeToString(result) + "*"})
	}
	start := time.Now()
	regs := []*regexp.Regexp{}
	for _, v := range whitelist {
		reg, err := regexp.Compile(v.Name)
		if err != nil {
			logging.Get().Warn().Msgf("compile failed %s", v.Name)
			continue
		}
		regs = append(regs, reg)
	}
	t.Log(len(regs))
	for _, v := range regs {
		for _, vv := range match {
			flag := v.Match([]byte(vv))
			if flag {
				t.Log("matched")
			}
		}
	}

	t.Log(time.Since(start))
}
