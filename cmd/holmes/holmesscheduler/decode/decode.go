package decode

import (
	"io/ioutil"

	"gitlab.com/piccolo_su/vegeta/pkg/cryption"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

func DoRulesDecode(thrFilePath string) ([]byte, error) {

	encryptionFileBytes, err := ioutil.ReadFile(thrFilePath)
	if err != nil {
		return nil, err
	}

	header, rulesContext, _, err := cryption.ReadRulesData(encryptionFileBytes)

	if err != nil {
		return nil, err
	}

	logging.GetLogger().Info().Msgf("Rules Version: %d %d", header.Version[0], header.Version[1])

	return rulesContext, err
}
