package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"gitlab.com/piccolo_su/vegeta/pkg/holmes"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	gpModel "gitlab.com/security-rd/go-pkg/model"
	gpMozart "gitlab.com/security-rd/go-pkg/mozart"
	"gopkg.in/yaml.v2"
)

func checkRulesDuplication(rules []gpModel.UserRuleYaml) error {
	ruleMap := make(map[string]struct{}, len(rules))
	listMap := make(map[string]struct{}, len(rules))
	macroMap := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		if rule.Name != "" {
			if _, ok := ruleMap[rule.Name]; ok {
				return fmt.Errorf("duplicate rule name: %s", rule.Name)
			}
			ruleMap[rule.Name] = struct{}{}
		} else if rule.Macro != "" {
			if _, ok := macroMap[rule.Macro]; ok {
				return fmt.Errorf("duplicate macro name: %s", rule.Macro)
			}
			macroMap[rule.Macro] = struct{}{}
		} else if rule.List != "" {
			if _, ok := listMap[rule.List]; ok {
				return fmt.Errorf("duplicate list name: %s", rule.List)
			}
			listMap[rule.List] = struct{}{}
		}

	}
	return nil
}

func checkRulesDuplicationV1V2(rules []model.RuleFromYaml) error {
	ruleMap := make(map[string]struct{}, len(rules))
	listMap := make(map[string]struct{}, len(rules))
	macroMap := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		if rule.Rule != "" {
			if _, ok := ruleMap[rule.Rule]; ok {
				return fmt.Errorf("duplicate rule name: %s", rule.Rule)
			}
			ruleMap[rule.Rule] = struct{}{}
		} else if rule.Macro != "" {
			if _, ok := macroMap[rule.Macro]; ok {
				return fmt.Errorf("duplicate macro name: %s", rule.Macro)
			}
			macroMap[rule.Macro] = struct{}{}
		} else if rule.List != "" {
			if _, ok := listMap[rule.List]; ok {
				return fmt.Errorf("duplicate list name: %s", rule.List)
			}
			listMap[rule.List] = struct{}{}
		}

	}
	return nil
}

func checkMarcoDefineOrder(userRules []gpModel.UserRuleYaml) error {
	usage := make(map[string]string)
	marcos := make([]gpModel.UserRuleYaml, 0)
	for i := range userRules {
		if gpMozart.IsURMarco(userRules[i]) {
			marcos = append(marcos, userRules[i])
		}
	}
	for i := range marcos {
		// build
		if marcos[i].Macro != "" {
			items := strings.Split(marcos[i].Condition, " ")
			for j := range items {
				if _, ok := usage[strings.TrimSpace(items[j])]; !ok {
					usage[strings.TrimSpace(items[j])] = marcos[i].Condition
				}
			}
		}
		if marcos[i].List != " " {
			for j := range marcos[i].Items {
				if _, ok := usage[strings.TrimSpace(marcos[i].Items[j])]; !ok {
					usage[strings.TrimSpace(marcos[i].Items[j])] = fmt.Sprintf("[%s]", strings.Join(marcos[i].Items, ", "))
				}
			}
		}
		// check
		if marcos[i].Macro != "" {
			if o, ok := usage[strings.TrimSpace(marcos[i].Macro)]; ok {
				return fmt.Errorf("use marco before define. marco: %s, use: %s", marcos[i].Macro, o)
			}
		}
		if marcos[i].List != "" {
			if o, ok := usage[strings.TrimSpace(marcos[i].List)]; ok {
				return fmt.Errorf("use marco before define. marco: %s, use: %s", marcos[i].List, o)
			}
		}
	}
	return nil
}

func checkRulesFile(in []byte) error {
	var userRules []gpModel.UserRuleYaml
	err := yaml.Unmarshal(in, &userRules)
	if err != nil {
		return err
	}
	err = checkRulesDuplication(userRules)
	if err != nil {
		return err
	}

	err = checkMarcoDefineOrder(userRules)
	if err != nil {
		return err
	}

	return nil
}

func checkRulesFileV1V2(in []byte) error {
	var rulesContext []model.RuleFromYaml
	err := yaml.Unmarshal(in, &rulesContext)
	if err != nil {
		return err
	}
	err = checkRulesDuplicationV1V2(rulesContext)
	if err != nil {
		return err
	}
	return nil
}

func writeOutputFile(fp *os.File, data []byte) error {
	_, err := fp.Write(data)
	if err != nil {
		return err
	}
	err = fp.Sync()
	if err != nil {
		return err
	}
	return nil
}

func main() {
	outputRulesFilename := flag.String("output",
		"./tensorsec-holmes.thr",
		"Binary for holmes update, `./tensorsec-holmes.thr` is an example.")

	inputRulesDirName := flag.String("input",
		"./holmes/rules",
		"Rules file dir for holmes to work, `./holmes/rules` is an example.")

	version := flag.String("version",
		"1.0",
		"Version for pack rulesfile, `1.0` is an example.")
	flag.Parse()

	ctx := context.Background()

	versionList := strings.Split(*version, ".")
	if len(versionList) != 2 {
		fmt.Printf("version number parse error. input: %s", *version)
		os.Exit(5)
	}
	versionNum := [2]uint16{0, 0}
	tmpInt, err := strconv.ParseUint(versionList[0], 10, 16)
	if err != nil {
		fmt.Println(err)
		os.Exit(6)
	}
	versionNum[0] = uint16(tmpInt)
	tmpInt, err = strconv.ParseUint(versionList[1], 10, 16)
	if err != nil {
		fmt.Println(err)
		os.Exit(7)
	}
	versionNum[1] = uint16(tmpInt)

	fp, err := os.Create(*outputRulesFilename)
	if err != nil {
		fmt.Printf("\033[1;37;41m%s\033[0m\n", err)
		os.Exit(1)
	}
	defer fp.Close()

	fileBytes, cconfigBytes := readBytesFromDir(*inputRulesDirName)
	var finalBytes []byte

	if versionNum[0] > 2 {
		userRules, _, err := mozart2UserRule(ctx, fileBytes)
		if err != nil {
			printYamlWithLineNo(fileBytes)
			fmt.Printf("\033[1;37;41m%s\033[0m\n", err)
			fp.Close()
			os.Exit(2)
		}
		finalBytes, err = yaml.Marshal(userRules)
		if err != nil {
			printYamlWithLineNo(finalBytes)
			fmt.Printf("\033[1;37;41m%s\033[0m\n", err)
			fp.Close()
			os.Exit(3)
		}

		if err = checkRulesFile(finalBytes); err != nil {
			printYamlWithLineNo(finalBytes)
			fmt.Printf("\033[1;37;41m%s\033[0m\n", err)
			fp.Close()
			os.Exit(4)
		}
	} else {
		finalBytes = fileBytes
		if err = checkRulesFileV1V2(finalBytes); err != nil {
			fmt.Printf("\033[1;37;41m%s\033[0m\n", err)
			fp.Close()
			os.Exit(14)
		}
	}

	finalBytes = append(finalBytes, '\n')
	finalBytes = append(finalBytes, cconfigBytes...)

	printYamlWithLineNo(finalBytes)
	thrBytes, err := holmes.ToThrBytes(finalBytes, versionNum)
	if err != nil {
		printYamlWithLineNo(finalBytes)
		fmt.Println(err)
		fp.Close()
		os.Exit(8)
	}
	err = writeOutputFile(fp, thrBytes)
	if err != nil {
		fmt.Println(err)
		fp.Close()
		os.Exit(9)
	}
}

// 1. 从路径中读取文件数据
// 2. 找到自定义规则，并分别返回
// 3. 将自定义规则相关的规则，放到规则包最前面。（优先级最高）
func readBytesFromDir(dirPath string) ([]byte, []byte) {
	fileInfos, err := os.ReadDir(dirPath)
	if err != nil {
		fmt.Println(err)
		os.Exit(10)
	}
	fileBytes := make([]byte, 0, 10000)
	partFileBytes := make([]byte, 0)
	cConfigBytes := make([]byte, 0)
	for _, fileInfo := range fileInfos {
		if fileInfo.IsDir() {
			continue
		} else if strings.Index(fileInfo.Name(), "custom_configs") >= 0 { // exclude custom_configs.yaml
			cConfigBytes, err = os.ReadFile(dirPath + "/" + fileInfo.Name())
			if err != nil {
				fmt.Println(err)
				os.Exit(11)
			}

		} else {
			partFileBytes, err = os.ReadFile(dirPath + "/" + fileInfo.Name())
			if err != nil {
				fmt.Println(err)
				os.Exit(12)
			}
		}
		fileBytes = append(fileBytes, append([]byte("\n\n"), partFileBytes...)...)
		partFileBytes = make([]byte, 0, 50)
	}

	// 获取自定义规则的规则名称
	cConfigRuleNames := []string{}
	sCConfig := string(cConfigBytes)
	sCParts := strings.Split(sCConfig, "rulesAppliedSteps:\n")
	if len(sCParts) == 1 { // 没有自定义规则，直接返回
		return fileBytes, cConfigBytes
	}
	sCParts = sCParts[1:]
	for i := range sCParts {
		sLines := strings.Split(sCParts[i], "\n")
		line := strings.TrimSpace(strings.ReplaceAll(sLines[0], "-", ""))
		if line != "" {
			cConfigRuleNames = append(cConfigRuleNames, line)
		}
	}

	// 调整自定义规则，放到最前面
	sFile := string(fileBytes)
	sParts := strings.Split(sFile, "\n-")
	if len(sParts) == 1 {
		fmt.Println("no rules?")
		os.Exit(13)
	}
	firstTitle := sParts[0]
	sNewCConfig := ""
	sNewOther := "" + firstTitle
	sParts = sParts[1:]
	for i := range sParts {
		sLines := strings.Split(sParts[i], "\n")
		if len(sLines) == 1 {
			continue
		}
		meetCConfig := false
		for j := range cConfigRuleNames {
			if strings.Index(sLines[0], cConfigRuleNames[j]) != -1 {
				sNewCConfig += "\n-" + sParts[i]
				meetCConfig = true
				break
			}
		}
		if !meetCConfig {
			sNewOther += "\n-" + sParts[i]
		}
	}
	fileBytes = []byte(sNewCConfig + sNewOther)

	return fileBytes, cConfigBytes
}

func printYamlWithLineNo(finalBytes []byte) {
	fmt.Println("---------- ---------- ---------- yaml start ---------- ---------- ---------- ")
	lines := strings.Split(string(finalBytes), "\n")
	for i := range lines {
		fmt.Printf("%05d: %s\n", i+1, lines[i])
	}
	fmt.Println("---------- ---------- ---------- yaml end ---------- ---------- ---------- ")
}
