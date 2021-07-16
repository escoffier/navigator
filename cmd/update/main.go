package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"gitlab.com/piccolo_su/vegeta/pkg/cryption"
	"io/ioutil"
	"os"
)

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
	//var 	version   	[2]uint16

	encode, decode := true, true
	if encode {
		fp, err := os.Create("./test/output.test")
		if err != nil {
			fmt.Println(err)
		}
		defer fp.Close()

		fileBytes, err := ioutil.ReadFile("./test/falco_rules.local.yaml")
		if err != nil {
			fmt.Println(err)
			return
		}

		data, md5, blockNum := cryption.EncryptionRules(fileBytes)
		header := &cryption.FileHeader{BlockNum: blockNum, Version: [2]uint16{1, 0}}
		header.Init(md5)

		err = writeOutputFile(fp, header, data)
		if err != nil {
			fmt.Println(err)
			return
		}
	}
	if decode {
		fileBytes, err := ioutil.ReadFile("./test/output.test")
		if err != nil {
			fmt.Println(err)
			return
		}

		header, rulesContext, _, err := cryption.ReadRulesData(fileBytes)

		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println("Version: ", header.Version[0], header.Version[1])

		rfp, err := os.Create("./test/output.yaml")
		if err !=nil {
			fmt.Println(err)
			return
		}
		defer rfp.Close()

		rfp.Write(rulesContext)
	}
}