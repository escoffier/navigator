package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"time"
)

func main() {
	cmd := NewCmd()
	err := cmd.Execute()
	if err != nil {
		log.Fatal(err)
	}
}

func NewCmd() *cobra.Command {
	var apiUrl, outputFile, consoleUrl, clusterKey string
	var apiID int64
	cmd := &cobra.Command{
		Use:  "apiscan",
		Long: "apiscan",
		RunE: func(cmd *cobra.Command, args []string) error {
			if apiID <= 0 {
				return errors.New("api ID must be greater than 0")
			}
			subModule := "webscan"
			oscmd := exec.Command("xray", "--config", "config.yaml", subModule, "--url", apiUrl, "--json-output", outputFile)
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
			reqUrl := fmt.Sprintf("%s%s", consoleUrl, fmt.Sprintf("/apiscan/clusters/%s/apis/%d/report", clusterKey, apiID))

			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
				},
				Timeout: 10 * time.Second,
			}

			_, err = client.Post(reqUrl, "application/json", bytes.NewBuffer(cliReqBytes))
			if err != nil {
				return err
			}
			return nil
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&apiUrl, "url", "https://vulnweb.tensorsecurity.cn/", "api url")
	flags.StringVar(&consoleUrl, "console", "https://vulnweb.tensorsecurity.cn/", "console url")
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
