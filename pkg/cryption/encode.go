package cryption

import (
	"crypto/md5"
)

func readBufN(p []byte, n int) (int, []byte) {
	if p == nil || len(p) <= 0 {
		return 0, nil
	}
	if n > len(p) {
		n = len(p)
	}
	return n, p[:n]

}

func EncryptionRules(fData []byte) ([]byte, []byte, uint32) {
	keyStr := "testtesttesttest"
	key := []byte(keyStr)
	writeBuf := make([]byte, 0)

	md5LoopValue := make([]byte, md5.Size)
	count := uint32(0)
	i := 0
	for ; i < len(fData); i += rulesBlockSize {
		n, buf := readBufN(fData[i:], rulesBlockSize)
		if 0 == n {
			break
		}
		buf = buf[:n]

		header := DataHeader{}
		encrypted := AesEncryptCFB(buf, key)
		headerBytes, err := header.dump(encrypted)
		if err != nil {
			return nil, nil, 0
		}

		dataBlock := append(headerBytes, encrypted...)
		tmpMD5 := md5.Sum(encrypted)
		tmp2MD5 := make([]byte, md5.Size)
		tmp2MD5 = tmpMD5[:md5.Size]
		md5LoopValue = xorBytes(md5LoopValue, tmp2MD5, md5.Size)
		writeBuf = append(writeBuf, dataBlock...)
		count = count + 1
	}
	return writeBuf, md5LoopValue, count
}
