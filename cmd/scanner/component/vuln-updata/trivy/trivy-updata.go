package trivy_updata

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/avast/retry-go"
	"github.com/boltdb/bolt"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/vuln-updata/register"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type TrivyUpdata struct {
	//db     *bolt.DB
	config TrivyConfig
}

type TrivyConfig struct {
	DbPath string
}

func init() {
	err := register.Register("trivy", openRegistry)
	if err != nil {
		logging.GetLogger().Err(err).Msg("init scannert db updater err")
	}
}

func openRegistry(registrableComponentConfig register.RegistrableComponentConfig, db *bolt.DB, dbPath string) (register.Registry, error) {
	var trivy TrivyUpdata
	trivy.config.DbPath = dbPath

	return &trivy, nil
}

func (t *TrivyUpdata) Updata(wg *sync.WaitGroup) {
	retryOptions := []retry.Option{
		retry.DelayType(retry.FixedDelay),
		retry.Attempts(10),
		retry.Delay(time.Duration(10) * time.Second),
	}
	defer wg.Done()
	ctx := context.Background()
	err := util.RetryWithBackoff(ctx, func() error {
		err := t.GetTrivyDb()
		if err != nil {
			if err.Error() == "equal" {
				return nil
			}
			logging.GetLogger().Error().Err(err).Msgf("scannert Updata will restart")
			return err
		}
		return nil
	}, retryOptions...)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msgf("scannert Updata error")
	}

}

func FileExists(path string) bool {
	_, err := os.Stat(path) //os.Stat获取文件信息

	if err != nil {
		return os.IsExist(err)
	}

	return true
}

func CheckDb(DbPath string, bucketName string, opts bolt.Options) error {
	fmt.Println("cehckout DB")
	if !FileExists(DbPath) {
		return fmt.Errorf("%v is not Exist", DbPath)
	}
	db, err := bolt.Open(DbPath, 0600, &opts)
	if err != nil {
		return err
	}
	defer db.Close()
	err = db.View(func(tx *bolt.Tx) error {
		testBucket := tx.Bucket([]byte(bucketName))
		if testBucket == nil {
			return fmt.Errorf("get %v Bucket failed", bucketName)
		}
		return nil
	})
	fmt.Println("check Down")
	return err
}

func (t *TrivyUpdata) GetTrivyDb() error {
	//fmt.Printf("DbPath is %v \n", t.config.DbPath)
	//time.Sleep(20 * time.Second) //改用通道
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Timeout: 30 * time.Second, Transport: tr, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	downClient := &http.Client{Timeout: 1800 * time.Second, Transport: tr}
	// var docVal string

	jumpUrl := "https://github.com/aquasecurity/trivy-db/releases/latest"

	request, err := http.NewRequest("GET", jumpUrl, nil) //2
	if err != nil {
		logging.GetLogger().Error().Msgf("new http request err")
		return fmt.Errorf("NewRequest failed from scannert")
	}

	resp, err := client.Do(request)
	if err != nil || (resp.StatusCode != 200 && resp.StatusCode != 302) {
		//fmt.Println(resp)
		if resp != nil {
			return fmt.Errorf("Connect Scannert version  code is %v", resp.StatusCode)
		} else {
			return fmt.Errorf("Connect Scannert version failed ")
		}
	}
	respLocation, err := resp.Location()
	if err != nil {
		return fmt.Errorf("Redirct Error %v ", err)
	}
	fmt.Println(respLocation)
	defer resp.Body.Close()

	trivyInitVersion := ""
	lastIndex := strings.Split(respLocation.String(), "/")
	trivyVersion := lastIndex[len(lastIndex)-1]
	if FileExists(filepath.Join(t.config.DbPath, "trivy_version")) {
		trivyVersionBytes, err := os.ReadFile(filepath.Join(t.config.DbPath, "trivy_version"))
		if err != nil {
			return fmt.Errorf("ReadFile Error %v", err)
		}
		trivyInitVersion = string(trivyVersionBytes)
	} else {
		trivyVersionBytes, err := os.ReadFile(filepath.Join(t.config.DbPath, "trivy_init_version"))
		if err != nil {
			return fmt.Errorf("ReadFile Error %v", err)
		}
		trivyInitVersion = string(trivyVersionBytes)
	}

	fmt.Printf("version :%v %v", trivyInitVersion, trivyVersion)
	if trivyInitVersion >= trivyVersion {
		logging.GetLogger().Info().Msgf("Version is equal,not check")
		return fmt.Errorf("equal")
	}

	dbUrl := "https://github.com/aquasecurity/trivy-db/releases/download/" + trivyVersion + "/trivy.db.gz"
	request, err = http.NewRequest("GET", dbUrl, nil) //2
	if err != nil {
		return fmt.Errorf("NewRequest failed from scannert")
	}
	resp, err = downClient.Do(request)
	if err != nil {
		return fmt.Errorf("Connect Body failed scannert")
	}
	defer resp.Body.Close()
	//reader := io.LimitReader(resp.Body, 1024*1024*100)
	logging.GetLogger().Info().Msg("scannert download down")
	file, _ := os.OpenFile(filepath.Join(t.config.DbPath, "trivy.db.gz"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0777)
	defer file.Close()
	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return fmt.Errorf("write db file err")
	}
	logging.GetLogger().Info().Msg("scannert ReadAll down")
	// err = os.WriteFile(t.config.DbPath+"trivy.db.gz", body, 0777)
	// if err != nil {
	// 	logging.GetLogger().Error().Msgf("failed to download %v", err)
	// 	return err
	// }

	logging.GetLogger().Info().Msg("scannert WriteFile down")
	osCmd := exec.Command("gunzip", "-f", filepath.Join(t.config.DbPath, "trivy.db.gz"))
	err = osCmd.Run()
	if err != nil {
		return fmt.Errorf("gunzip error %v: ", err)
	}
	logging.GetLogger().Info().Msg("scannert gunzip down")
	var options bolt.Options
	options.Timeout = time.Second * 5
	if CheckDb(filepath.Join(t.config.DbPath, "trivy.db"), "vulnerability", options) == nil {
		osCmd = exec.Command("mv", "-f", filepath.Join(t.config.DbPath, "trivy.db"), filepath.Join(t.config.DbPath, "last_trivy.db"))
		err = osCmd.Run()
		if err != nil {
			return fmt.Errorf("mv error %v ", err)
		}
		err = os.WriteFile(filepath.Join(t.config.DbPath, "trivy_version"), []byte(trivyVersion), 0777)
		if err != nil {
			return fmt.Errorf("Write Version error %v ", err)
		}
	}
	fmt.Println("scannert down")
	return nil
}
