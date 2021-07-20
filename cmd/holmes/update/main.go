package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"gitlab.com/piccolo_su/vegeta/pkg/cryption"
	"gitlab.com/piccolo_su/vegeta/pkg/echelper"
	"gitlab.com/piccolo_su/vegeta/pkg/lang"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/pb"
)

type lateversionResp struct {
	Data struct {
		Item struct {
			Data                 string   `json:"data"`
			Closerules           []string `json:"closedRules"`
			LatestDataVersion    int      `json:"latestDataVersion"`
			LatestSettingVersion int      `json:"latestSettingVersion"`
			DataChanged          bool     `json:"dataChanged"`
			SettingChanged       bool     `json:"settingChanged"`
		} `json:"item"`
	} `json:"data"`
}

func getData(token, url string, currentVersion, currentSetVersion int) (lateversionResp, error) {
	client := &http.Client{}
	url = fmt.Sprintf("%s?curDataVersion=%d&curSettingVersion=%d", url, currentVersion, currentSetVersion)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Error(err)
		return lateversionResp{}, err
	}
	req.Header.Set("X-Tensorsec-cicd-key", token)
	resp, err := client.Do(req)
	if err != nil {
		log.Error(err)
		return lateversionResp{}, err
	}
	body, _ := ioutil.ReadAll(resp.Body)
	respStru := lateversionResp{}
	err = json.Unmarshal(body, &respStru)
	if err != nil {
		return lateversionResp{}, err
	}
	return respStru, nil
}

func closeRules(streamBytes []byte, closeRules []string) []byte {
	rulesStr := string(streamBytes)
	addStr := "  enabled: false\n"
	for _, v := range closeRules {
		repStr := "- rule: " + v + "\n"
		index := strings.Index(rulesStr, repStr)
		if index < 0 {
			continue
		}
		rulesStr = strings.Replace(rulesStr, repStr, repStr+addStr, len(addStr))

	}
	retBytes := []byte(rulesStr)
	return retBytes
}

type kv struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func sendRulesToEventCenter(rulesData []byte) error {
	const (
		timeout  = time.Second * 5
		module   = "ContainerSecurity"
		category = "ATT&CK"
	)
	var fDataRules []model.RuleFromYaml
	err := yaml.Unmarshal(rulesData, &fDataRules)
	if err != nil {
		return err
	}

	var rules = make([]*pb.DetectionRule, 0, len(fDataRules))
	for _, item := range fDataRules {
		if len(item.Rule) == 0 || len(item.Priority) == 0 {
			continue
		}

		ruleType, err := model.GetInfoFromOutput("rule_type=", item.Output)
		if err != nil {
			ruleType = "Other"
		}
		ruleTypeZh := model.TranslateRuleType(ruleType)
		descZh := ""
		zhMsg, err := model.GetInfoFromOutput("zh_msg=", item.Output)
		if err != nil {
			continue
		}

		if len(strings.Split(zhMsg, ";")) < 2 {
			descZh = strings.Split(zhMsg, ";")[0]
		} else {
			descZh = strings.Split(zhMsg, ";")[1]
		}

		var rule = &pb.DetectionRule{
			Module:      module,
			Category:    category,
			Name:        item.Rule,
			Description: item.Desc,
			Severity:    uint32(model.Str2SeverityNum(item.Priority)),
			CustomKV: []*pb.MultiLanguageKV{
				{
					KVHash: map[string]*pb.KV{
						string(lang.LanguageEN): {Key: "ruleType", Value: ruleType},
						string(lang.LanguageZH): {Key: "规则类型", Value: ruleTypeZh},
					},
				},
			},
			MultiLanguage: map[string]*pb.MultiLanguageValue{
				"description": {
					ValueHash: map[string]string{
						string(lang.LanguageZH): descZh,
					},
				},
			},
		}

		if len(item.Suggestion) > 0 {
			var kvHash = make(map[string]*pb.KV, len(item.Suggestion))
			for l, v := range item.Suggestion {
				if l == "" || v == nil {
					continue
				}
				kvHash[l] = &pb.KV{
					Key:   v.Key,
					Value: v.Value,
				}
			}
			if len(kvHash) > 0 {
				rule.CustomKV = append(rule.CustomKV, &pb.MultiLanguageKV{
					KVHash: kvHash,
				})
			}
		}

		rules = append(rules, rule)
	}

	cli, err := echelper.NewEventCenterClient()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return cli.ResetCategoryRules(ctx, module, category, rules)
}

func updateLoop(token, url string, dataVersion, settingVersion int) {
	//time.Sleep(600 * time.Second)
	for {
		time.Sleep(30 * time.Second)
		httpStreamData, err := getData(token, url, dataVersion, settingVersion)
		if httpStreamData.Data.Item.DataChanged || httpStreamData.Data.Item.SettingChanged || err != nil {
			break
		}
	}
	os.Exit(0)
}

func startHolmesWithDefaultRules(cmdLine string) (err error) {
	log.Debug("Start with default rules")

	defaultRulesFile := "/etc/holmes/holmes_rules.yaml"

	encryptionFileBytes, err := ioutil.ReadFile("/etc/holmes/tensorsec-holmes-rules.thr")
	if err != nil {
		log.Error(err)
		os.Exit(0)
	}

	header, rulesContext, _, err := cryption.ReadRulesData(encryptionFileBytes)
	if err != nil {
		log.Error(err)
		os.Exit(0)
	}
	log.Info("Rules Version: ", header.Version[0], header.Version[1])

	err = sendRulesToEventCenter(rulesContext)
	if err != nil {
		log.Error(err)
		err = nil
	}

	fp, err := os.Create(defaultRulesFile)
	if err != nil {
		log.Error(err)
		os.Exit(0)
	}

	_, err = fp.Write(rulesContext)
	if err != nil {
		log.Error(err)
		os.Exit(0)
	}

	fp.Sync()
	fp.Close()

	name := strings.Split(cmdLine, " ")[0]
	argsList := strings.Split(cmdLine, " ")[1:]
	argsList = append(argsList, "-r", defaultRulesFile)
	log.Debug(name, argsList)

	var stderr bytes.Buffer
	osCmd := exec.Command(name, argsList...)
	osCmd.Stdout = os.Stdout
	osCmd.Stderr = &stderr
	err = osCmd.Start()

	loadingStr := fmt.Sprintf("Loading rules from file %s", defaultRulesFile)
	for {
		timer := time.NewTimer(30 * time.Second)
		<-timer.C
		if strings.Contains(stderr.String(), loadingStr) {
			fmt.Print(stderr.String())
			break
		}

	}
	time.Sleep(30 * time.Second)
	os.Remove(defaultRulesFile)
	osCmd.Wait()
	return err
}

func startHolmesProcess(cmdLine, rulesFile string) error {

	name := strings.Split(cmdLine, " ")[0]
	argsList := strings.Split(cmdLine, " ")[1:]
	argsList = append(argsList, "-r", rulesFile)
	osCmd := exec.Command(name, argsList...)

	log.Debug(name, argsList)
	//var out bytes.Buffer
	var stderr bytes.Buffer
	osCmd.Stdout = os.Stdout
	osCmd.Stderr = &stderr
	err := osCmd.Start()
	if err != nil {
		log.Error(err)
	}

	loadingStr := fmt.Sprintf("Loading rules from file %s", rulesFile)
	for {
		timer := time.NewTimer(30 * time.Second)
		<-timer.C

		if strings.Contains(stderr.String(), loadingStr) {

			fmt.Print(stderr.String())
			break
		}

	}
	time.Sleep(30 * time.Second)
	os.Remove(rulesFile)
	osCmd.Wait()
	err = startHolmesWithDefaultRules(cmdLine)
	if err != nil {
		log.Error(err)
		return err
	}
	return nil
}

func main() {

	consoleAddr := "tensorsec-console:8889"
	if len(os.Getenv("CONSOLE_HTTP_ADDR")) > 0 {
		consoleAddr = os.Getenv("CONSOLE_HTTP_ADDR")
	}
	url := "http://" + consoleAddr

	outputRulesFilename := flag.String("output",
		"/etc/falco/falco_rules.local.yaml",
		"Binary for holmes update, `/etc/falco/holmes_rules.yaml` is an example.")
	cmdLineArgs := flag.String("holmes-args",
		"/usr/bin/holmes --cri /run/containerd/containerd.sock -K /var/run/secrets/kubernetes.io/serviceaccount/token -k https://$(KUBERNETES_SERVICE_HOST) -pk",
		"Holmes start args")
	debug := flag.Bool("debug",
		false,
		"Run in debug mode with extended logging")

	flag.Parse()

	if *debug {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}

	token := "dGVuc29yc2VjLWNpY2QtdXNlcg==.qBFMMAvbbm3afG3y42CqKaN7WQe4Q7hiqtg5Jzwen7tWHhZG16P62kvv"
	httpStreamData, err := getData(token, url+"/api/openapi/ATTCK/latestData", -1, -1)
	if err != nil {
		log.Error(err)
		startHolmesWithDefaultRules(*cmdLineArgs)
		os.Exit(0)
	}

	tmpBytes, err := base64.StdEncoding.DecodeString(httpStreamData.Data.Item.Data)
	if err != nil {
		log.Error(err)
		startHolmesWithDefaultRules(*cmdLineArgs)
		os.Exit(0)
	}
	header, rulesContext, _, err := cryption.ReadRulesData(tmpBytes)
	go updateLoop(token, url+"/api/openapi/ATTCK/latestData", httpStreamData.Data.Item.LatestDataVersion, httpStreamData.Data.Item.LatestSettingVersion)
	if err != nil {
		log.Error(err)
		startHolmesWithDefaultRules(*cmdLineArgs)
		os.Exit(0)
	}

	writeBytes := closeRules(rulesContext, httpStreamData.Data.Item.Closerules)

	err = sendRulesToEventCenter(writeBytes)
	if err != nil {
		log.Error(err)
	}

	log.Info("Rules Version: ", header.Version[0], header.Version[1])

	rfp, err := os.Create(*outputRulesFilename)
	if err != nil {
		log.Error(err)
		startHolmesWithDefaultRules(*cmdLineArgs)
		os.Exit(0)
	}

	_, err = rfp.Write(writeBytes)
	if err != nil {
		log.Error(err)
		startHolmesWithDefaultRules(*cmdLineArgs)
		os.Exit(0)
	}
	rfp.Sync()
	rfp.Close()

	err = startHolmesProcess(*cmdLineArgs, *outputRulesFilename)
	if err != nil {
		log.Error(err)
		os.Exit(0)
	}
	os.Exit(0)
}
