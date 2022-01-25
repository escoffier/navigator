package pkg

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/avast/retry-go"
	"github.com/rs/zerolog/log"

	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

var (
	CopyString          = "\nCOPY dp.so /tmp/dp.so \nCOPY file-checker /tmp/file-checker \nRUN /tmp/file-checker"
	LocalFileCheckerURL = "/api/openapi/scanner/imagereject/result/file-checker"
)

func getAbsolutePath() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", err
	}
	res, _ := filepath.EvalSymlinks(filepath.Dir(exePath))
	return res, nil
}

func createFileChecker(dockerBuildPath string, filename string, resp *http.Response) error {
	filePath := ""
	var err error
	if dockerBuildPath == "." || dockerBuildPath == "./" {
		filePath, err = getAbsolutePath()
		if err != nil {
			return err
		}
	} else {
		filePath = dockerBuildPath
	}
	fp := filepath.Join(filePath, filename)
	if util.FileExists(fp) { //文件已存在，则直接返回
		return nil
	}
	file, err := os.Create(fp)
	if err != nil {
		return err
	}
	err = os.Chmod(fp, 0777)
	if err != nil {
		return err
	}
	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return err
	}
	return nil
}

func getFileChecker(dockerBuildPath string, filename string, maxSecond int, consoleURL string, apikey string) error {
	tryInterval := 30
	tryCount := maxSecond / tryInterval
	retryOptions := []retry.Option{
		retry.MaxDelay(time.Duration(tryInterval) * time.Second),
		retry.DelayType(retry.FixedDelay),
		retry.Attempts(uint(tryCount)),
		retry.Delay(time.Duration(tryInterval) * time.Second),
	}
	ctx := context.Background()
	client := &http.Client{Timeout: time.Duration(maxSecond) * time.Second}
	err := util.RetryWithBackoff(ctx, func() error {
		if consoleURL[len(consoleURL)-1] == '/' {
			consoleURL = consoleURL[:len(consoleURL)-1]
		}

		request, _ := http.NewRequest("GET", consoleURL+LocalFileCheckerURL+"?name="+filename, nil)
		request.Header.Add("X-Tensorsec-cicd-key", apikey)
		request.Header.Add("Content-Type", "application/json")

		resp, err := client.Do(request)
		if err != nil {
			log.Error().Err(err).Msgf("request Filechecker err: %v,try again", err)
			return err
		}
		if resp.StatusCode != 200 {
			errRes, _ := ioutil.ReadAll(resp.Body)
			fmt.Println(request.URL)
			log.Warn().Msgf("get Filechecker err,try again.%v", string(errRes))
			return fmt.Errorf("response err.%d", resp.StatusCode)
		}
		defer resp.Body.Close()
		err = createFileChecker(dockerBuildPath, filename, resp)
		if err != nil {
			log.Warn().Msgf("createFileChecker err,try again.%v", err)
			return err
		}
		return nil
	}, retryOptions...)

	if err != nil {
		return err
	}
	return nil
}

func writeDockerFile(dockerFilePath string) error {
	fileBody, err := os.ReadFile(dockerFilePath)
	if err != nil {
		return err
	}
	if strings.Contains(string(fileBody), CopyString) {
		return nil
	}
	fp, err := os.OpenFile(dockerFilePath, os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	n, _ := fp.Seek(0, 2)
	_, err = fp.WriteAt([]byte(CopyString), n)
	if err != nil {
		return err
	}
	return nil
}

func ReinforceImage(maxSecond int, consoleURL string, apikey string) error {
	dockerFilePath := os.Getenv("CICDDockerPath")
	dockerBuildPath := os.Getenv("CICDDockerBuildPath")
	log.Info().Msgf("CICDDockerPath:%v CICDDockerBuildPath:%v\n", dockerFilePath, dockerBuildPath)
	if dockerFilePath == "" || dockerBuildPath == "" {
		return nil
	}

	err := getFileChecker(dockerBuildPath, "file-checker", maxSecond, consoleURL, apikey)
	if err != nil {
		return err
	}

	err = getFileChecker(dockerBuildPath, "dp.so", maxSecond, consoleURL, apikey)
	if err != nil {
		return err
	}
	log.Info().Msg("getFileChecker succeed")

	err = writeDockerFile(dockerFilePath)
	if err != nil {
		return err
	}
	log.Info().Msg("writeDockerFile succeed")
	return nil
}
