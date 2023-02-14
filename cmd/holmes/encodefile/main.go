package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"gitlab.com/piccolo_su/vegeta/pkg/holmes"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gopkg.in/yaml.v2"
)

func checkRulesDuplication(rules []model.RuleFromYaml) error {
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

func checkRulesFile(in []byte) error {
	var rulesContext []model.RuleFromYaml
	err := yaml.Unmarshal(in, &rulesContext)
	if err != nil {
		return err
	}
	err = checkRulesDuplication(rulesContext)
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

	fp, err := os.Create(*outputRulesFilename)
	if err != nil {
		fmt.Printf("\033[1;37;41m%s\033[0m\n", err)
		os.Exit(1)
	}
	defer fp.Close()

	fileBytes := readBytesFromDir(*inputRulesDirName)

	if err = checkRulesFile(fileBytes); err != nil {
		fmt.Printf("\033[1;37;41m%s\033[0m\n", err)
		fp.Close()
		os.Exit(2)
	}
	versionList := strings.Split(*version, ".")
	if len(versionList) != 2 {
		fmt.Printf("version number parse error. input: %s", *version)
		fp.Close()
		os.Exit(3)
	}
	versionNum := [2]uint16{0, 0}
	tmpInt, err := strconv.ParseUint(versionList[0], 10, 16)
	if err != nil {
		fmt.Println(err)
		fp.Close()
		os.Exit(4)
	}
	versionNum[0] = uint16(tmpInt)
	tmpInt, err = strconv.ParseUint(versionList[1], 10, 16)
	if err != nil {
		fmt.Println(err)
		fp.Close()
		os.Exit(5)
	}
	versionNum[1] = uint16(tmpInt)

	thrBytes, err := holmes.ToThrBytes(fileBytes, versionNum)
	if err != nil {
		fmt.Println(err)
		fp.Close()
		os.Exit(6)
	}
	err = writeOutputFile(fp, thrBytes)
	if err != nil {
		fmt.Println(err)
		fp.Close()
		os.Exit(6)
	}
}

func readBytesFromDir(dirPath string) []byte {
	fileInfos, err := ioutil.ReadDir(dirPath)
	if err != nil {
		fmt.Println(err)
		os.Exit(7)
	}
	fileBytes := make([]byte, 0, 50)
	partFileBytes := make([]byte, 0, 50)
	for _, fileInfo := range fileInfos {
		if fileInfo.IsDir() {
			partFileBytes = readBytesFromDir(dirPath + "/" + fileInfo.Name())
		} else {
			partFileBytes, err = ioutil.ReadFile(dirPath + "/" + fileInfo.Name())
			if err != nil {
				fmt.Println(err)
				os.Exit(8)
			}
		}
		fileBytes = append(fileBytes, append([]byte("\n\n"), partFileBytes...)...)
		partFileBytes = make([]byte, 0, 50)
	}

	return fileBytes
}
