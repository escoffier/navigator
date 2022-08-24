//go:build local
// +build local

package offline

import (
	"io/ioutil"
	"os"
	"testing"

	"gitlab.com/security-rd/go-pkg/cryption"
t 	log "github.com/sirupsen/logrus"
)

func TestOfflineFile(t *testing.T) {
	// inputRulesFilename := "/test.zip"
	// outputRulesFilename := "/dbZip.thr"
	// version := "11111.111"
	// fp, err := os.Create(outputRulesFilename)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }
	// defer fp.Close()

	// fileBytes, err := ioutil.ReadFile(inputRulesFilename)
	// data, md5, blockNum := cryption.EncryptionDbs(fileBytes)
	// versionList := strings.Split(version, ".")
	// versionNum := [2]uint16{0, 0}
	// tmpInt, err := strconv.ParseUint(versionList[0], 10, 16)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }
	// versionNum[0] = uint16(tmpInt)
	// tmpInt, err = strconv.ParseUint(versionList[1], 10, 16)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }
	// versionNum[1] = uint16(tmpInt)
	// header := &cryption.FileHeader{BlockNum: blockNum, Version: versionNum}
	// header.DbInit(md5)

	// err = writeOutputFile(fp, header, data)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }
	encryptionFileBytes, err := ioutil.ReadFile("/dbZip.thr")
	if err != nil {
		log.Error(err)
		os.Exit(0)
	}
	outheader, rulesContext, _, err := cryption.ReadRulesData(encryptionFileBytes)
	if err != nil {
		log.Error(err)
		os.Exit(0)
	}
	log.Info("Rules Version: ", outheader.Version[0], outheader.Version[1])
	dstZip := "testdata/outputzip.zip"
	fp, err := os.Create(dstZip)
	if err != nil {
		log.Error(err)
		os.Exit(0)
	}
	_, err = fp.Write(rulesContext)
	if err != nil {
		log.Error(err)
		os.Exit(0)
	}
	_ = fp.Sync()
	_ = fp.Close()
}
