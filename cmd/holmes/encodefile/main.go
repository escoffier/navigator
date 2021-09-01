package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"gitlab.com/piccolo_su/vegeta/pkg/cryption"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

func checkRulesFile(in []byte) error {
	var rulesContext []model.RuleFromYaml
	err := yaml.Unmarshal(in, &rulesContext)
	if err != nil {
		return err
	}
	return nil
}

func writeOutputFile(fp *os.File, header *cryption.FileHeader, data []byte) error {

	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, header)
	if err != nil {
		return err
	}
	_, err = fp.Write(buf.Bytes())
	if err != nil {
		return err
	}
	_, err = fp.Write(data)
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

	inputRulesFilename := flag.String("input",
		"./falco_rules.local.yaml",
		"Rules file for holmes to work, `./falco_rules.local.yaml` is an example.")

	version := flag.String("version",
		"1.0",
		"Version for pack rulesfile, `1.0` is an example.")
	flag.Parse()

	fp, err := os.Create(*outputRulesFilename)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer fp.Close()

	fileBytes, err := ioutil.ReadFile(*inputRulesFilename)
	if err != nil {
		fmt.Println(err)
		return
	}
	if err = checkRulesFile(fileBytes); err != nil {
		fmt.Println(err)
		return
	}
	data, md5, blockNum := cryption.EncryptionRules(fileBytes)
	versionList := strings.Split(*version, ".")
	versionNum := [2]uint16{0, 0}
	tmpInt, err := strconv.ParseUint(versionList[0], 10, 16)
	if err != nil {
		fmt.Println(err)
		return
	}
	versionNum[0] = uint16(tmpInt)
	tmpInt, err = strconv.ParseUint(versionList[1], 10, 16)
	if err != nil {
		fmt.Println(err)
		return
	}
	versionNum[1] = uint16(tmpInt)
	header := &cryption.FileHeader{BlockNum: blockNum, Version: versionNum}
	header.Init(md5)

	err = writeOutputFile(fp, header, data)
	if err != nil {
		fmt.Println(err)
		return
	}
}
