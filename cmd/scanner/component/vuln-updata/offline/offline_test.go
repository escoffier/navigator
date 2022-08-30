//go:build local
// +build local

package offline

import (
	"io/ioutil"
	"os"
	"testing"

	log "github.com/sirupsen/logrus"
	"gitlab.com/security-rd/go-pkg/cryption"
)

func TestOfflineFile(t *testing.T) {
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
