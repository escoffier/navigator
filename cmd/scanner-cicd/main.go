package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/avast/retry-go"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"gitlab.com/piccolo_su/vegeta/pkg/util"

	// "gitlab.com/piccolo_su/vegeta/pkg/logging"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type ScanOneCICDResultRequest struct {
	ImageID int64  `json:"id"`
	Library string `json:"library"`
}
type accountRes struct {
	UserName string `json:"username"`
	PassWord string `json:"password"`
}
type accountdata struct {
	Items []accountRes `json:"items"`
}
type accountInfo struct {
	ApiVersion string      `json:"apiVersion"`
	Data       accountdata `json:"data"`
}

type ScanOneForCICDResponse struct {
	IsScan bool `json:"is_scan"`
	Safe   bool `json:"safe"`

	RejectMsg [][]string `json:"reject_msg"`
	Vulu      [][]string `json:"vulu"`
	Sensitive [][]string `json:"sensitive"`
	Virus     [][]string `json:"virus"`
	Webshell  [][]string `json:"webshell"`
}

type resdata struct {
	Item ScanOneCICDResultRequest `json:"item"`
}

type resultData struct {
	Item ScanOneForCICDResponse `json:"item"`
}

type resJson struct {
	ApiVersion string  `json:"apiVersion"`
	Data       resdata `json:"data"`
}
type resultInfo struct {
	ApiVersion string     `json:"apiVersion"`
	Data       resultData `json:"data"`
}
type jsonData struct {
	Image     string `json:"image"`
	MaxSecond string `json:"max_second"`
	Library   string `json:"library"`
	Insecure  bool   `json:"insecure"`
}

func outputTable(data [][]string) {
	table := tablewriter.NewWriter(os.Stdout)
	if len(data) != 0 {
		table.SetHeader(data[0])
		for k := range data {
			if k == 0 {
				continue
			}
			table.Append(data[k])
		}
		table.Render()
	}
}

func cicdExec(ctx context.Context, image string, apikey string, maxSecond int, consoleUrl string, bufRegistryUrl string, debug bool, insecure bool, wg *sync.WaitGroup) {
	defer wg.Done()
	if debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
	if consoleUrl[len(consoleUrl)-1] != '/' {
		consoleUrl += "/"
	}
	bufRegistryUrl = strings.TrimRight(bufRegistryUrl, "/")
	accountInfo := accountInfo{}
	log.Info().Msgf("image=%s maxSecond=%d consoleUrl=%s bufRegistryUrl=%s aki_key=%s \n", image, maxSecond, consoleUrl, bufRegistryUrl, apikey)
	// 获取自己仓库的用户名密码
	client := &http.Client{Timeout: time.Duration(maxSecond) * time.Second}
	err := util.RetryWithBackoff(ctx, func() error {
		getLibraryUrl := consoleUrl + "api/openapi/scanner/register/registries?usetype=2"
		log.Info().Msgf("get cache certificate url  : %s\n", getLibraryUrl)
		request, err := http.NewRequest("GET", getLibraryUrl, nil) // 2
		if err != nil {
			log.Error().Err(err).Msgf("new http request err")
			return err
		}
		request.Header.Add("X-Tensorsec-cicd-key", apikey)
		request.Header.Add("Content-Type", "application/json")
		resp, err := client.Do(request)
		if err != nil {
			log.Error().Err(err).Msg("get cache certificate err,try again")
			return err
		}
		err = json.NewDecoder(resp.Body).Decode(&accountInfo)
		if err != nil {
			log.Error().Err(err).Msg("unmarshal resp Body error")
		}
		resp.Body.Close()
		log.Info().Msgf("get cache certificate success")
		return nil
	}, retry.Attempts(3))

	if err != nil {
		log.Error().Err(err).Msg("get cache certificate err")
		os.Exit(2)
	}

	// push到自己的仓库中
	if len(accountInfo.Data.Items) == 0 {
		log.Error().Msg("未查询到中转仓库")
		os.Exit(2)
	}

	osCmd := exec.Command("docker", "login", "-u", accountInfo.Data.Items[0].UserName, "-p", accountInfo.Data.Items[0].PassWord, bufRegistryUrl)
	var out bytes.Buffer
	var stderr bytes.Buffer
	osCmd.Stdout = &out
	osCmd.Stderr = &stderr

	log.Debug().Msgf("%v", osCmd.Args)

	err = osCmd.Run()
	if err != nil {
		log.Error().Err(err).Msgf("docker login err :%v %v %v\n", err, stderr.String(), out.String())
		if strings.Contains(stderr.String(), "Error") {
			os.Exit(2)
		}
		os.Exit(2)
	}

	index := strings.Index(image, "/")
	tmpimage := image[index+1:]
	tmpimage = bufRegistryUrl + "/" + tmpimage
	stderr.Reset()
	out.Reset()
	osCmd = exec.Command("docker", "tag", image, tmpimage)
	err = osCmd.Run()
	log.Debug().Msgf("%v", osCmd.Args)
	if err != nil {
		log.Error().Err(err).Msgf("docker tag err :%v %v %v\n", err, stderr.String(), out.String())
		os.Exit(2)
	}

	stderr.Reset()
	out.Reset()
	osCmd = exec.Command("docker", "push", tmpimage)
	err = osCmd.Run()
	log.Debug().Msgf("%v", osCmd.Args)
	if err != nil {
		log.Error().Err(err).Msgf("docker push err :%v %v %v\n", err, stderr.String(), out.String())
		if strings.Contains(stderr.String(), "Error") {
			os.Exit(2)
		}
		// return
	}

	log.Info().Msg("start scanning, please wait...")

	// 调用cicd接口
	data := jsonData{}
	data.Insecure = insecure
	data.Image = image
	data.Library = bufRegistryUrl
	data.MaxSecond = fmt.Sprintf("%d", maxSecond)
	jsonSrt, err := json.Marshal(data)
	if err != nil {
		log.Error().Err(err).Msg("marshal json error")
	}
	getScanUrl := consoleUrl + "api/openapi/scanner/imagereject/scanone/cicd"
	resInfo := resJson{}
	err = util.RetryWithBackoff(ctx, func() error {
		request, _ := http.NewRequest("POST", getScanUrl, bytes.NewBuffer(jsonSrt))
		request.Header.Add("X-Tensorsec-cicd-key", apikey)
		request.Header.Add("Content-Type", "application/json")

		log.Debug().Msgf("%v", request)

		resp, err := client.Do(request)
		if err != nil {
			log.Error().Err(err).Msgf("request scan err: %v,try again", err)
			return err
		}
		if resp.StatusCode != 200 {
			errRes, _ := ioutil.ReadAll(resp.Body)
			log.Error().Msg(string(errRes))
			return fmt.Errorf("request scan err: %d, try again", resp.StatusCode)
		} else {
			err = json.NewDecoder(resp.Body).Decode(&resInfo)
			if err != nil {
				log.Error().Err(err).Msg("response err")
				return err
			}
		}
		return nil
	}, retry.Attempts(3))
	if err != nil {
		log.Error().Err(err).Msgf("request scan err %v", err)
		os.Exit(2)
	}

	log.Debug().Msgf("返回数据为%v", resInfo)
	log.Info().Msgf("触发cicd扫描成功")
	getScanResultUrl := consoleUrl + "api/openapi/scanner/imagereject/result/cicd"
	tmpData := resInfo.Data.Item
	resJsonStr, err := json.Marshal(tmpData)
	if err != nil {
		log.Error().Err(err).Msg("marshal json error")
	}
	resultInfo := resultInfo{}

	tryInterval := 30
	tryCount := maxSecond / tryInterval
	retryOptions := []retry.Option{
		retry.MaxDelay(time.Duration(tryInterval) * time.Second),
		retry.DelayType(retry.FixedDelay),
		retry.Attempts(uint(tryCount)),
		retry.Delay(time.Duration(tryInterval) * time.Second),
	}
	err = util.RetryWithBackoff(ctx, func() error {
		request, _ := http.NewRequest("POST", getScanResultUrl, bytes.NewBuffer(resJsonStr))
		request.Header.Add("X-Tensorsec-cicd-key", apikey)
		request.Header.Add("Content-Type", "application/json")
		log.Debug().Msgf("%v", request)
		resp, err := client.Do(request)
		if err != nil {
			log.Error().Err(err).Msgf("request scan result err :%v,try again", err)
			return err
		}
		if resp.StatusCode != 200 {
			errRes, _ := ioutil.ReadAll(resp.Body)
			log.Warn().Msgf("get scan result err,try again.%v", string(errRes))
			return fmt.Errorf("response err.%d", resp.StatusCode)
		} else {
			err = json.NewDecoder(resp.Body).Decode(&resultInfo)
			if err != nil {
				log.Error().Err(err).Msg("decode response data err")
				return err
			}
			if resultInfo.Data.Item.IsScan {
				return nil
			}
		}
		return nil
	}, retryOptions...)

	if err != nil {
		log.Error().Msgf("get scan result err.%v", err)
		os.Exit(2)
	}

	log.Debug().Msgf("scan result:%v,is scan:%v", resultInfo.Data.Item.Safe, resultInfo.Data.Item.IsScan)

	// 输出结果
	outputTable(resultInfo.Data.Item.RejectMsg)
	outputTable(resultInfo.Data.Item.Vulu)
	outputTable(resultInfo.Data.Item.Sensitive)
	outputTable(resultInfo.Data.Item.Virus)
	outputTable(resultInfo.Data.Item.Webshell)
	if !resultInfo.Data.Item.Safe {
		log.Info().Msgf("scan found vulnerabilities.")
		os.Exit(2)
	}
	log.Info().Msgf("scan image vulnerabilities pass.")
	os.Exit(0)
}

func main() {
	var image string
	var max_second int
	var console_url string
	var bufRegistry_url string
	var debug bool
	var apikey string
	var insecure bool
	rootCmd := &cobra.Command{
		Use:   "tensor-scanner-cicd",
		Short: "tensor-scanner-cicd tool",
		Long:  `tensor-scanner-cicd tool with scanner use`,
		Run: func(cmd *cobra.Command, args []string) {
			image, _ := cmd.Flags().GetString("image-name")
			max_second, _ := cmd.Flags().GetInt("timeout")
			console_url, _ := cmd.Flags().GetString("tensorsec-cloud-url")
			bufRegistry_url, _ := cmd.Flags().GetString("tensorsec-remote-cache")
			apikey, _ := cmd.Flags().GetString("token")
			debug, _ := cmd.Flags().GetBool("debug")
			insecure, _ := cmd.Flags().GetBool("insecure")
			if image == "" {
				log.Error().Msg("镜像参数不得为空")
				os.Exit(2)
			}
			if console_url == "" {
				log.Error().Msg("console链接不能为空")
				os.Exit(2)
			}
			if bufRegistry_url == "" {
				log.Error().Msg("临时仓库地址不能为空")
				os.Exit(2)
			}
			if apikey == "" {
				log.Error().Msg("token不能为空")
				os.Exit(2)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(max_second))
			defer cancel()
			var wg sync.WaitGroup
			wg.Add(1)
			go cicdExec(ctx, image, apikey, max_second, console_url, bufRegistry_url, debug, insecure, &wg)
			wg.Wait()
		},
	}
	log.Logger = log.With().Caller().Logger()
	rootCmd.Flags().StringVarP(&image, "image-name", "i", "", "[REGISTRY_HOST[:REGISTRY_PORT]/]REPOSITORY[:TAG]") // 1
	rootCmd.Flags().IntVarP(&max_second, "timeout", "t", 300, "timeout(unit:second)")
	rootCmd.Flags().StringVarP(&console_url, "tensorsec-cloud-url", "c", "", "tensorsec-cloud-url")
	rootCmd.Flags().StringVarP(&bufRegistry_url, "tensorsec-remote-cache", "r", "", "tensorsec scanner cache address")
	rootCmd.Flags().StringVarP(&apikey, "token", "k", "", "for authentication")
	rootCmd.Flags().BoolVarP(&debug, "debug", "", false, "")
	rootCmd.Flags().BoolVarP(&insecure, "insecure", "s", false, "allow insecurity connections when use http")
	if err := rootCmd.Execute(); err != nil {
		// logging.GetLogger().Error().Err(err).Msg("Failed to startup")
		log.Error().Err(err).Msg("Failed to startup")
		os.Exit(1)
	}
}
