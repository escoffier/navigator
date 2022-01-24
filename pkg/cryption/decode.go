package cryption

import (
	"crypto/md5"
	"errors"
	"fmt"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

var (
	ErrChecksum = errors.New("checksum error")
)
const (
	dataBlockSize  = 32
	rulesBlockSize = 16
	fileHeaderSize = 36
	dataHeaderSize = 20
)

func xorBytes(b1, b2 []byte, len int) []byte {
	i := 0
	for i = 0; i < len; i++ {
		b1[i] = b1[i] ^ b2[i]
	}
	return b1
}

func cmpMD5(origin [md5.Size]byte, check []byte, offset uint8) bool {
	i := uint8(0)
	for ; i < md5.Size; i++ {
		if origin[i] != check[(i+offset)%md5.Size] {
			return true
		}
	}
	return false
}

func cmpHeader(header FileHeader) bool {
	for k, v := range []byte("tensor") {
		if header.MagicNum[k] != v {
			return true
		}
	}
	return false
}

func decodeBlock(fData []byte, blockSize uint8) ([]byte, []byte, error) {
	copyData := make([]byte, len(fData))
	copy(copyData, fData)
	keyStr := "testtesttesttest"
	key := []byte(keyStr)
	buf := make([]byte, 32)
	retBuf := make([]byte, 0)

	i := 0
	blockSizeInt := int(blockSize)
	md5LoopValue := make([]byte, md5.Size)

	for ; i*blockSizeInt < len(copyData); i++ {
		l := i * blockSizeInt
		var r int
		if ((i + 1) * blockSizeInt) < len(copyData) {
			r = (i + 1) * blockSizeInt
		} else {
			r = len(copyData)
		}
		buf = copyData[l:r]
		header, buf, err := readDataBlock(buf)
		if err != nil {
			fmt.Println(err)
			return nil, nil, err
		}
		tmpMD5 := make([]byte, md5.Size)
		tmpMD5 = header.MD5Checksum[:md5.Size]
		md5LoopValue = xorBytes(md5LoopValue, tmpMD5, md5.Size)
		decrypted := AesDecryptCFB(buf, key)

		retBuf = append(retBuf, decrypted...)
	}
	return retBuf, md5LoopValue, nil
}

func ReadRulesData(fData []byte) (FileHeader, []byte, []byte, error) {
	header, err := readHeader(fData)
	if err != nil {
		return FileHeader{}, nil, nil, err
	}

	if cmpHeader(header) {
		return FileHeader{}, nil, nil, errors.New("header error")
	}

	content := fData[header.Offset:]

	rulesContext, md5Value, err := decodeBlock(content, header.BlockSize)

	if err != nil {
		return FileHeader{}, nil, nil, err
	}

	if cmpMD5(header.MD5, md5Value, header.MD5Offset) {
		logging.GetLogger().Error().Msg("checksum error")
		return FileHeader{}, nil, nil,ErrChecksum
	}

	return header, rulesContext, md5Value, nil
}
