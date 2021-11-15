package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/avast/retry-go"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner-cicd/pkg"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner-cicd/pkg/cmd"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner-cicd/pkg/output"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner-cicd/pkg/request"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner-cicd/pkg/structures"
	trustimage "gitlab.com/piccolo_su/vegeta/cmd/scanner-cicd/pkg/trust-image"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

var (
	image           string
	maxSecond       int
	consoleUrl      string
	bufRegistryUrl  string
	debug           bool
	apikey          string
	insecure        bool
	privateKeyFile  string
	reinforceEnable bool
)

func OnlyLogFileNameFormat(i interface{}) string {
	c, ok := i.(string)
	if !ok {
		return fmt.Sprintf("%s", i)
	}
	_, filename := filepath.Split(c)
	return filename
}

var rootCmd = &cobra.Command{
	Use:   "scanner-cicd",
	Short: "scanner-cicd tool",
	Long:  `scanner-cicd tool with scanner use`,
	Run: func(cmd *cobra.Command, args []string) {
		checkArgs()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(maxSecond))
		defer cancel()
		run(ctx)
	},
}

var (
	outputFunc    func(info structures.ResultInfo) error
	httpClient    *request.Request
	privateClient *trustimage.Client
)

func init() {
	rootCmd.Flags().StringVarP(&image, "image-name", "i", "", "[REGISTRY_HOST[:REGISTRY_PORT]/]REPOSITORY[:TAG]") // 1
	rootCmd.Flags().IntVarP(&maxSecond, "timeout", "t", 300, "timeout(unit:second)")
	rootCmd.Flags().StringVarP(&consoleUrl, "cloud-url", "c", "", "cloud-url")
	rootCmd.Flags().StringVarP(&bufRegistryUrl, "remote-cache", "r", "", "scanner cache address")
	rootCmd.Flags().StringVarP(&apikey, "token", "k", "", "for authentication")
	rootCmd.Flags().BoolVarP(&debug, "debug", "", false, "")
	rootCmd.Flags().BoolVarP(&insecure, "insecure", "s", false, "allow insecurity connections when use http")
	rootCmd.Flags().StringVarP(&privateKeyFile, "private-file", "p", "", "location of private key")
	rootCmd.Flags().BoolVarP(&reinforceEnable, "reinforce-enbale", "j", false,
		"reinforce image enable(it shouble use before build and cicd),use env CICDDockerPath and CICDDockerBuildPath")
}

func main() {

	if err := rootCmd.Execute(); err != nil {
		// log.Error().Err(err).Msg("Failed to startup")
		log.Error().Err(err).Msg("Failed to startup")
		os.Exit(1)
	}
}

func run(ctx context.Context) {
	if reinforceEnable {
		log.Info().Msg("reinforceEnable is true,It will execute reinfroce image,if you need cicd,please set this filed false")
		err := pkg.ReinforceImage(maxSecond, consoleUrl, apikey)
		if err != nil {
			log.Error().Err(err).Msg("Failed reinfoce Image")
			os.Exit(2)
		}

		return
	}

	accountInfo := structures.AccountInfo{}
	// 获取自己仓库的用户名密码
	err := util.RetryWithBackoff(ctx, func() error {
		return httpClient.Do("/api/openapi/scanner/register/registries?usetype=2", http.MethodGet, nil, &accountInfo)
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

	// 登录docker
	stdout, stderr, err := cmd.RunCmd(
		"docker", "login", "-u",
		accountInfo.Data.Items[0].UserName, "-p", accountInfo.Data.Items[0].PassWord, bufRegistryUrl,
	)
	if err != nil {
		log.Error().Err(err).Msgf("docker login err :%v %v %v\n", err, stderr.String(), stdout.String())
		os.Exit(2)
	}

	newTag := pkg.ImageReTag(image, bufRegistryUrl)

	stdout, stderr, err = cmd.RunCmd("docker", "tag", image, newTag)
	if err != nil {
		log.Error().Err(err).Msgf("docker tag err :%v %v %v\n", err, stderr.String(), stdout.String())
		os.Exit(2)
	}

	stdout, stderr, err = cmd.RunCmd("docker", "push", newTag)
	if err != nil {
		log.Error().Err(err).Msgf("docker push err :%v %v %v\n", err, stderr.String(), stdout.String())
		if strings.Contains(stderr.String(), "Error") {
			os.Exit(2)
		}
	}

	log.Info().Msg("start scanning, please wait...")

	// 调用cicd接口
	data := structures.JsonData{
		Insecure:  insecure,
		Image:     image,
		Library:   bufRegistryUrl,
		MaxSecond: strconv.Itoa(maxSecond),
	}

	jsonSrt, err := json.Marshal(data)
	if err != nil {
		log.Error().Err(err).Msg("marshal json error")
	}
	resInfo := structures.ResJson{}
	err = util.RetryWithBackoff(ctx, func() error {
		return httpClient.Do("/api/openapi/scanner/imagereject/scanone/cicd", http.MethodPost, bytes.NewBuffer(jsonSrt), &resInfo)
	}, retry.Attempts(3))
	if err != nil {
		log.Error().Err(err).Msgf("request scan err %v", err)
		os.Exit(2)
	}

	log.Debug().Msgf("返回数据为%+v", resInfo)
	log.Info().Msgf("触发cicd扫描成功")

	tmpData := resInfo.Data.Item
	resJsonStr, err := json.Marshal(tmpData)
	if err != nil {
		log.Error().Err(err).Msg("marshal json error")
	}
	resultInfo := structures.ResultInfo{}

	tryInterval := 30
	tryCount := maxSecond / tryInterval
	retryOptions := []retry.Option{
		retry.MaxDelay(time.Duration(tryInterval) * time.Second),
		retry.DelayType(retry.FixedDelay),
		retry.Attempts(uint(tryCount)),
		retry.Delay(time.Duration(tryInterval) * time.Second),
	}
	err = util.RetryWithBackoff(ctx, func() error {
		return httpClient.Do("/api/openapi/scanner/imagereject/result/cicd", http.MethodPost, bytes.NewBuffer(resJsonStr), &resultInfo)
	}, retryOptions...)

	if err != nil {
		log.Error().Err(err).Msgf("get scan result err.%v", err)
		os.Exit(2)
	}

	log.Debug().Msgf("scan result:%v,is scan:%v", resultInfo.Data.Item.Safe, resultInfo.Data.Item.IsScan)

	// 输出结果
	err = outputFunc(resultInfo)
	if err != nil {
		log.Error().Err(err).Msgf("failed to output")
		os.Exit(2)
	}

	if !resultInfo.Data.Item.Safe {
		log.Info().Msgf("scan found vulnerabilities.")
		os.Exit(2)
	}

	if privateClient != nil {
		//  可信镜像 将镜像的 digest 和 image_name 签名后发送到 scanner
		err = privateClient.Sign(ctx, image, insecure, bufRegistryUrl)
		if err != nil {
			log.Error().Msgf("sign image err.%v", err)
			os.Exit(2)
		}
	}

	log.Info().Msgf("scan image vulnerabilities pass.")
}

// 检查参数是否正确
func checkArgs() {
	var err error
	zOutput := zerolog.ConsoleWriter{
		Out:        os.Stdout,
		NoColor:    true,
		TimeFormat: time.RFC3339,
		FormatLevel: func(i interface{}) string {
			return strings.ToUpper(fmt.Sprintf("%s:", i))
		},
		FormatCaller: OnlyLogFileNameFormat,
	}
	log.Logger = log.Output(zOutput).With().Caller().Logger()

	if image == "" {
		log.Error().Msg("镜像参数不得为空")
		os.Exit(2)
	}
	if consoleUrl == "" {
		log.Error().Msg("console链接不能为空")
		os.Exit(2)
	}
	if bufRegistryUrl == "" {
		log.Error().Msg("临时仓库地址不能为空")
		os.Exit(2)
	}
	if apikey == "" {
		log.Error().Msg("token不能为空")
		os.Exit(2)
	}

	if debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
	outputFunc = output.Terminal
	httpClient, err = request.NewRequest(apikey, consoleUrl, maxSecond)
	if err != nil {
		log.Error().Err(err).Msg("Failed to initial http client")
		os.Exit(1)
	}

	if privateKeyFile != "" {
		privateClient, err = trustimage.NewClient(privateKeyFile, httpClient)
		if err != nil {
			log.Error().Err(err).Msg("Failed to initial private client")
			os.Exit(1)
		}
	}

	log.Info().Msgf("image=%s maxSecond=%d consoleUrl=%s bufRegistryUrl=%s aki_key=%s \n", image, maxSecond, consoleUrl, bufRegistryUrl, apikey)
}
