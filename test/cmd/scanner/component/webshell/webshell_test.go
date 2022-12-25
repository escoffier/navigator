package webshell_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	scannermodel "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
)

func TestCode(t *testing.T) {
	GetCode(t)
}

func GetCode(t *testing.T) ([]scannermodel.ProblemCode, error) {
	filePath := "testFile"
	datas := [][]byte{}
	if util.FileExists(filePath) {
		data, err := os.ReadFile(filePath)
		if err != nil {
			logging.Get().Err(err).Msg("read file error")
			//response.JSONError(ctx, fmt.Errorf("read file error"))
			return nil, err
		}
		datas = bytes.Split(data, []byte{'\n'})
	}
	tmpCode := []scannermodel.BeforeDecode{}
	decodeCode := []scannermodel.WebshellCode{}
	tmpCode = append(tmpCode, scannermodel.BeforeDecode{})
	tmpCode = append(tmpCode, scannermodel.BeforeDecode{})
	tmpCode[0].Data = "PCA="
	tmpCode[0].Offset = 10682
	tmpCode[1].Data = "ZXhlYyg="
	tmpCode[1].Offset = 13985
	for k := range tmpCode {
		decode, err := base64.StdEncoding.DecodeString(tmpCode[k].Data)
		if err != nil {
			logging.Get().Err(err).Msg("decode base64 error")
		}
		code := scannermodel.WebshellCode{}
		code.Data = decode
		code.Offset = tmpCode[k].Offset
		decodeCode = append(decodeCode, code)
	}
	res := []scannermodel.ProblemCode{}
	resStr := []string{}
	lenth := 0
	line := 0
	for k := range datas {
		tmpPro := scannermodel.ProblemCode{}
		tmpPro.Data = datas[k]
		line++
		for kk, v := range decodeCode {
			if v.Offset >= int64(lenth) && v.Offset <= int64(lenth)+int64(len(datas[k])) {
				fmt.Println(v.Offset, int64(lenth)+int64(len(datas[k])))
				byteData := []byte(v.Data)
				cutLen := int64(lenth) + int64(len(datas[k])) - v.Offset
				proLen := v.Offset + int64(len(byteData))
				if proLen > int64(lenth)+int64(len(datas[k])) {
					//fmt.Printf("%v %v %v %s\n", proLen, cutLen, len(byteData), string(byteData))
					proData := byteData[:cutLen+1]
					tmpPro.Problem = append(tmpPro.Problem, string(proData))
					if cutLen+1 < int64(len(byteData)) {
						decodeCode[kk].Data = byteData[cutLen+1:]
						decodeCode[kk].Offset += cutLen + 1
					}
				} else {
					resStr = append(resStr, fmt.Sprintf("%s %v\n", string(datas[k]), line))
					tmpPro.Problem = append(tmpPro.Problem, string(v.Data))
				}
			}
		}
		lenth += len(datas[k]) + 1
		if len(tmpPro.Problem) > 0 {
			str := base64.StdEncoding.EncodeToString([]byte(tmpPro.Problem[0]))
			tmpPro.Problem[0] = str
		}
		res = append(res, tmpPro)
	}
	for k := range res {
		if len(res[k].Problem) > 0 {
			fmt.Println(res[k].Problem)
		}
	}

	assert.Equal(t, "echo <<< EOF 228\n", resStr[0])
	assert.Equal(t, "$os=exec(\"uname\"); 337\n", resStr[1])
	return res, nil
}
