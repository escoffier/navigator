package util

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"os"
	"reflect"
	"strings"

	"github.com/golang/gddo/httputil/header"
	jsoniter "github.com/json-iterator/go"
	"github.com/rs/zerolog/log"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

func SortOrderToInt(sortOrder string) int {
	if sortOrder == "asc" {
		return 1
	} else if sortOrder == "desc" {
		return -1
	}
	logging.GetLogger().Warn().Str("sortOrder", sortOrder).Msg("Unknown sortOrder string, can be asc/desc.")
	return 1
}

func DecodeJSONBody(w http.ResponseWriter, r *http.Request, dst interface{}) error {
	if reflect.ValueOf(dst).Kind() != reflect.Ptr {
		return errors.New("Expected dst to be pointer")
	}

	if r.Header.Get("Content-Type") != "" {
		value, _ := header.ParseValueAndParams(r.Header, "Content-Type")
		if value != "application/json" {
			return errors.New("The http header is not application/json")
		}
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1048576)

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	err := dec.Decode(&dst)
	if err != nil {
		return err
	}

	if dec.More() {
		return errors.New("Request body must only contain a single JSON object")
	}

	return nil
}

func CloseBodyWithLog(body io.ReadCloser) {
	defer func() {
		// prevent close it twice causing panic
		if r := recover(); r != nil {
			logging.GetLogger().Error().Msgf("Panic when closing ReadCloser: %v", r)
		}
	}()
	if body != nil {
		err := body.Close()
		if err != nil {
			log.Warn().Err(err).Msg("Failed to close body, but ignoring")
		}
	}
}

func AppendIfMissing(s []string, i string) []string {
	for _, ele := range s {
		if ele == i {
			return s
		}
	}
	return append(s, i)
}

func ContainsString(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func RemoveScoredNotScoredFrom(thing string) string {
	thing = strings.ReplaceAll(thing, " (Not Scored)", "")
	thing = strings.ReplaceAll(thing, " ( Not Scored)", "")
	thing = strings.ReplaceAll(thing, " (Scored)", "")
	return thing
}

func DesEncrypt(origData, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	origData = PKCS5Padding(origData, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, key)
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

func PKCS5Padding(cipherText []byte, blockSize int) []byte {
	padding := blockSize - len(cipherText)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(cipherText, padText...)
}

func DesDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, key)
	origData := make([]byte, len(crypted))
	// origData := crypted
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS5UnPadding(origData)
	// origData = ZeroUnPadding(origData)
	return origData, nil
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	// 去掉最后一个字节 unpadding 次
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

// GetMixedSetForString 取交集，但是但一个为空时，就返回另一个集合，而不是返回空
func GetMixedSetForString(pre, after []string) []string {
	res := make([]string, 0)
	if len(pre) == 0 {
		return after
	}
	if len(after) == 0 {
		return pre
	}
	preMap := make(map[string]int)
	for _, p := range pre {
		preMap[p] = 1
	}
	for _, p := range after {
		if preMap[p] == 1 {
			res = append(res, p)
			preMap[p]++ // 去重
		}
	}
	return res
}

// GetMixedSetForInt64 取交集，但是但一个为空时，就返回另一个集合，而不是返回空
func GetMixedSetForInt64(pre, after []int64) []int64 {
	pre = append(pre, after...)

	preMap := make(map[int64]int)
	res := make([]int64, 0)
	for _, p := range pre {
		if preMap[p] < 1 {
			res = append(res, p)
			preMap[p]++ // 去重
		}
	}
	return res
}

func MinInt(res ...int) int {
	if len(res) == 0 {
		return 0
	}
	ans := math.MaxInt64
	for _, r := range res {
		if r < ans {
			ans = r
		}
	}
	return ans
}

func DeepCopy(dst, src interface{}) error {
	eventData, err := jsoniter.Marshal(src)
	if err != nil {
		logging.GetLogger().Error().Msgf("deep marshal errror:%+v", err)
	}
	return jsoniter.Unmarshal(eventData, &dst)
}

func FileExists(path string) bool {
	_, err := os.Stat(path) //os.Stat获取文件信息

	if err != nil {
		if os.IsExist(err) {
			return true
		}
		return false
	}

	return true
}

func IsPostgresDuplicateError(err error) bool {
	if err == nil {
		return false
	}

	return strings.Contains(strings.ToLower(err.Error()), "duplicate")
}

func ImageUUID(image string) uint32 {
	im := strings.TrimPrefix(image, "http://") // trimPrefix http or https
	im = strings.TrimPrefix(image, "https://")
	return GenerateUUID(im)
}
