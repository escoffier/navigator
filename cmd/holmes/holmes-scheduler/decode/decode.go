package decode

import (
	"fmt"
	"io/ioutil"
	"log"

	"gitlab.com/piccolo_su/vegeta/pkg/cryption"
)

func DoRulesDecode(thrFilePath string) ([]byte, error) {

	fmt.Println("thr file path: ", thrFilePath)

	encryptionFileBytes, err := ioutil.ReadFile(thrFilePath)
	if err != nil {
		return nil, err
	}

	header, rulesContext, _, err := cryption.ReadRulesData(encryptionFileBytes)

	if err != nil {
		return nil, err
	}

	log.Println("Rules Version: ", header.Version[0], header.Version[1])

	return rulesContext, err
}
