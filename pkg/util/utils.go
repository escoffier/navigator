package util

import (
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/shopspring/decimal"

	"github.com/golang/gddo/httputil/header"
	json "github.com/json-iterator/go"

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
			logging.GetLogger().Warn().Err(err).Msg("Failed to close body, but ignoring")
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

// GetIntersectionSetForInt64 取交集
func GetIntersectionSetForInt64(pre, after []int64) []int64 {

	preMap := make(map[int64]struct{})
	afterMap := make(map[int64]struct{})
	for i := range pre {
		preMap[pre[i]] = struct{}{}
	}
	for i := range after {
		afterMap[after[i]] = struct{}{}
	}
	ans := make([]int64, 0)
	for k := range preMap {
		if _, ok := afterMap[k]; ok {
			ans = append(ans, k)
		}
	}

	return ans
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
	eventData, err := json.Marshal(src)
	if err != nil {
		logging.GetLogger().Error().Msgf("deep marshal errror:%+v", err)
	}
	return json.Unmarshal(eventData, &dst)
}

func PathExists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	return false
}

func FileExists(path string) bool {
	_, err := os.Stat(path) // os.Stat获取文件信息

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

func DeDuplicationInt64Slice(va []int64) []int64 {
	exit := make(map[int64]struct{})
	ans := make([]int64, 0, len(va))
	for i := range va {
		if _, ok := exit[va[i]]; !ok {
			ans = append(ans, va[i])
			exit[va[i]] = struct{}{}
		}
	}
	return ans
}

func DeDuplicationUint64Slice(va []uint64) []uint64 {
	exit := make(map[uint64]struct{})
	ans := make([]uint64, 0, len(va))
	for i := range va {
		if _, ok := exit[va[i]]; !ok {
			ans = append(ans, va[i])
			exit[va[i]] = struct{}{}
		}
	}
	return ans
}

func DeDuplicationStringSlice(va []string) []string {
	exit := make(map[string]struct{})
	ans := make([]string, 0, len(va))
	for i := range va {
		if _, ok := exit[va[i]]; !ok {
			ans = append(ans, va[i])
			exit[va[i]] = struct{}{}
		}
	}
	return ans
}

func Uint64SliceToStringSlice(value []uint64) []string {
	res := make([]string, len(value))
	for i := range value {
		res[i] = fmt.Sprintf("%d", value[i])
	}
	return res
}

func GetImageUrl(image string) (string, error) {
	var nameOpts []name.Option
	nameOpts = append(nameOpts, name.Insecure)

	ref, err := name.ParseReference(image, nameOpts...)
	if err != nil {
		return "", err
	}
	url := ref.Context().RegistryStr()
	return url, nil
}

func JoinInt64Slice(data []int64, join string) string {
	if len(data) == 0 {
		return ""
	}

	res := make([]string, len(data))
	for i := range data {
		res[i] = strconv.Itoa(int(data[i]))
	}
	return strings.Join(res, join)
}

func ByteToMB(b int) string {
	if b <= 0 {
		return ""
	}
	mb := float64(b) / (1024 * 1024)
	f, _ := decimal.NewFromFloat(mb).Round(2).Float64()
	return ToString(f) + "MB"
}

func ToString(value interface{}) string {
	return fmt.Sprintf("%v", value)
}
