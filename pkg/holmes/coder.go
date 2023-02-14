package holmes

import (
	"bytes"
	"encoding/binary"

	"gitlab.com/security-rd/go-pkg/cryption"
)

func ToThrBytes(ruleBytes []byte, versionNum [2]uint16) ([]byte, error) {
	data, md5, blockNum := cryption.EncryptionRules(ruleBytes)
	header := &cryption.FileHeader{BlockNum: blockNum, Version: versionNum}
	header.Init(md5)

	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, header)
	if err != nil {
		return nil, err
	}
	
	thrBytes := make([]byte, 0, buf.Len() + len(data))
	thrBytes = append(thrBytes, buf.Bytes()...)
	thrBytes = append(thrBytes, data...)
	return thrBytes, nil
}
