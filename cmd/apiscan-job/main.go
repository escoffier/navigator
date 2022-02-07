package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

const (
	defaultTimeout = 10 * time.Second
)

func main() {
	cmd := NewCmd()
	err := cmd.Execute()
	if err != nil {
		log.Fatal(err)
	}
}

func NewCmd() *cobra.Command {
	var apiURL, outputFile, consoleURL, clusterKey string
	var apiID int64
	cmd := &cobra.Command{
		Use:  "apiscan",
		Long: "apiscan",
		RunE: func(cmd *cobra.Command, args []string) error {
			if apiID <= 0 {
				return errors.New("api ID must be greater than 0")
			}
			subModule := "webscan"
			oscmd := exec.Command("xray", "--config", "config.yaml", subModule, "--basic", apiURL, "--json-output", outputFile)
			oscmd.Stdout = os.Stdout
			err := oscmd.Run()
			if err != nil {
				return err
			}

			postScanResult := ""
			if PathExists(outputFile) {
				f, err := os.Open(outputFile)
				if err != nil {
					return err
				}
				result, err := ioutil.ReadAll(f)
				if err != nil {
					return err
				}
				postScanResult = string(result)
			}

			cliReq := struct {
				ScanResult string `json:"scanResult"`
			}{
				ScanResult: postScanResult,
			}

			cliReqBytes, _ := json.Marshal(&cliReq)
			reqURL := fmt.Sprintf("%s%s", consoleURL, fmt.Sprintf("/apiscan/clusters/%s/apis/%d/report", clusterKey, apiID))

			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true, //nolint
					},
				},
				Timeout: defaultTimeout,
			}

			resp, err := client.Post(reqURL, "application/json", bytes.NewBuffer(cliReqBytes))
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			return nil
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&apiURL, "url", "http://vulnweb.test.cn/", "api url")
	flags.StringVar(&consoleURL, "console", "http://vulnweb.test.cn/", "console url")
	flags.StringVar(&outputFile, "output", "/app/result.json", "json output file name")
	flags.StringVar(&clusterKey, "cluster", "", "cluster key")
	flags.Int64Var(&apiID, "api", 0, "api ID")
	return cmd
}

func PathExists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	return false
}
