package util

import (
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/golang/gddo/httputil/header"
	"github.com/google/go-containerregistry/pkg/name"
	json "github.com/json-iterator/go"
	"github.com/shopspring/decimal"
	"github.com/yeka/zip"

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

	// max 3mb
	r.Body = http.MaxBytesReader(w, r.Body, 3<<20)

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

func ContainsLowerString(s []string, e string) bool {
	for _, a := range s {
		if strings.ToLower(a) == strings.ToLower(e) {
			return true
		}
	}
	return false
}

func ContainsInt(s []int, e int) bool {
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

type Int64s []int64

func (vi Int64s) Len() int {
	return len(vi)
}

func (vi Int64s) Less(i, j int) bool {
	return vi[i] < vi[j]
}

func (vi Int64s) Swap(i, j int) {
	vi[i], vi[j] = vi[j], vi[i]
}

func SortInt64Slice(data []int64) []int64 {
	sort.Sort(Int64s(data))
	return data
}

func TripSpaceSlice(data []string) []string {
	for i := range data {
		data[i] = strings.TrimSpace(data[i])
	}
	return data
}

func DuplicateInt64Slice(va []int64) []int64 {
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

func DuplicateIntSlice(va []int) []int {
	exit := make(map[int]struct{})
	ans := make([]int, 0, len(va))
	for i := range va {
		if _, ok := exit[va[i]]; !ok {
			ans = append(ans, va[i])
			exit[va[i]] = struct{}{}
		}
	}
	return ans
}

func DuplicateUint64Slice(va []uint64) []uint64 {
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

func DuplicateUint32Slice(va []uint32) []uint32 {
	exit := make(map[uint32]struct{})
	ans := make([]uint32, 0, len(va))
	for i := range va {
		if _, ok := exit[va[i]]; !ok {
			ans = append(ans, va[i])
			exit[va[i]] = struct{}{}
		}
	}
	return ans
}

func DuplicateStringSlice(va []string) []string {
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

func DeDupArray[T any](va []T, keyFunc func(t T) string) []T {
	exit := make(map[string]struct{})
	ans := make([]T, 0, len(va))
	for i := range va {
		if _, ok := exit[keyFunc(va[i])]; !ok {
			ans = append(ans, va[i])
			exit[keyFunc(va[i])] = struct{}{}
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

func ToString(value interface{}) string {
	return fmt.Sprintf("%v", value)
}

func InstallType(osFamily string) string {
	switch strings.ToLower(osFamily) {
	case "ubuntu", "debian":
		return "apt-get update  &&  apt upgrade -y "
	case "centos", "fedora":
		return "yum upgrade -y "
	case "alpine":
		return "apk update && apk add --upgrade -y "
	}
	return ""
}

func MkdirIfNotExist(path string, remove bool) error {
	if remove {
		// 先删除
		_ = os.RemoveAll(path)
	}

	stat, err := os.Stat(path)
	if err == nil {
		if stat.IsDir() {
			return nil
		} else {
			// 先删除这个文件再创建
			if err := os.Remove(path); err != nil {
				return err
			}
			return os.MkdirAll(path, os.ModePerm)
		}
	}
	if os.IsNotExist(err) {
		return os.MkdirAll(path, os.ModePerm)
	}
	return err
}

func RandPassword(passwordLength int) (string, error) {
	rand.Seed(time.Now().UnixNano())

	// 密码长度
	if passwordLength < 6 {
		return "", fmt.Errorf("passwordLength less than 6")
	}

	// 可用于密码的字符集，包含大写字母、小写字母、数字和特殊字符
	characters := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-="

	// 特殊字符集
	specialCharacters := "!@#$%^&*()_+-="

	// 生成随机字节数组
	randomBytes := make([]byte, passwordLength-1)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}

	// 使用 characters 中的字符生成密码
	password := ""
	for i := 0; i < passwordLength-1; i++ {
		password += string(characters[int(randomBytes[i])%len(characters)])
	}

	// 随机插入一个特殊字符
	specialChar := string(specialCharacters[rand.Intn(len(specialCharacters))])
	specialIdx := rand.Intn(passwordLength)
	password = password[:specialIdx] + specialChar + password[specialIdx:]

	return password, nil
}

func ListDeduplicate[T comparable](list []T) []T {
	newList := make([]T, 0, len(list))
	vset := make(map[T]struct{}, len(list))
	for _, v := range list {
		if _, exist := vset[v]; !exist {
			newList = append(newList, v)
			vset[v] = struct{}{}
		}
	}
	return newList
}

// Unzip decompress zip file to directory
func Unzip(zipFile, destDir, passwd string) error {
	zipReader, err := zip.OpenReader(zipFile)
	if err != nil {
		return err
	}
	defer func() { _ = zipReader.Close() }()

	for _, f := range zipReader.File {
		if f.IsEncrypted() {
			f.SetPassword(passwd)
		}
		// path := filepath.Join(destDir, f.Name)
		if f.FileInfo().IsDir() {
			err = os.MkdirAll(destDir, os.ModePerm)
			if err != nil {
				return err
			}
		} else {
			if err = os.MkdirAll(filepath.Dir(destDir), os.ModePerm); err != nil {
				return err
			}

			inFile, err := f.Open()
			if err != nil {
				return err
			}

			outFile, err := os.OpenFile(destDir, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
			if err != nil {
				_ = inFile.Close()
				return err
			}

			_, err = io.Copy(outFile, inFile)
			_ = inFile.Close()
			_ = outFile.Close()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// CopyFile copies the file content from scr to dst
func CopyFile(src, dst string) (int64, error) {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return 0, fmt.Errorf("file (%s) stat error: %w", src, err)
	}

	if !sourceFileStat.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer destination.Close()
	n, err := io.Copy(destination, source)
	return n, err
}

const (
	defaultGrpcTimeout = 600
	GrpcStreamKey      = "scanner-grpc"
	GrpcFmt            = "%s@%s"
)

func ImageSecGrpcTimeOut() int64 {
	t := os.Getenv("IMAGE_SEC_GRPC_TIME_OUT")
	if len(t) == 0 {
		return defaultGrpcTimeout
	}
	val, err := strconv.Atoi(t)
	if err != nil {
		return defaultGrpcTimeout
	}
	return int64(val)
}

// ScannerClusterManagerGrpcStreamKey grpc stream key used for scanner connecting to cluster manager
func ScannerClusterManagerGrpcStreamKey(clusterKey string) string {
	return fmt.Sprintf(GrpcFmt, clusterKey, GrpcStreamKey)
}

// ScannerConsoleGrpcStreamKey grpc stream key used for scanner connecting to console
func ScannerConsoleGrpcStreamKey() string {
	return fmt.Sprintf(GrpcFmt, "console", GrpcStreamKey)
}

func ParseByteSize(b int64) string {
	if b <= 0 {
		return ""
	}
	if b <= 1024 {
		return ToString(b) + "B"
	}

	if b <= 1024*1024 {
		mbs, _ := decimal.NewFromFloat(float64(b) / (1024)).Round(2).Float64()
		return ToString(mbs) + "KB"
	}
	if b <= 1024*1024*1024 {
		mbs, _ := decimal.NewFromFloat(float64(b) / (1024 * 1024)).Round(2).Float64()
		return ToString(mbs) + "M"
	}
	mbs, _ := decimal.NewFromFloat(float64(b) / (1024 * 1024 * 1024)).Round(2).Float64()
	return ToString(mbs) + "G"
}

func GetTimeUnixMilli(ti *time.Time) int64 {
	if ti == nil || ti.IsZero() {
		return 0
	}
	return ti.UnixMilli()
}

func IsEmpty(str string) bool {
	return strings.TrimSpace(str) == ""
}

func SplitUint64(str string) []uint64 {
	split := strings.Split(str, ",")
	ans := make([]uint64, 0)
	for i := range split {
		ui, _ := strconv.ParseUint(split[i], 10, 64)
		if ui > 0 {
			ans = append(ans, ui)
		}
	}
	return ans
}

func ConnectUint64(uid []uint64) string {
	if len(uid) == 0 {
		return ""
	}
	ans := make([]string, 0)
	for i := range uid {
		u := strconv.FormatUint(uid[i], 10)
		if u != "" {
			ans = append(ans, u)
		}
	}
	return strings.Join(ans, ",")
}

func DaySinceUnixEpoch(date time.Time) int64 {
	date = date.UTC()
	unixEpoch := time.Date(1970, time.January, 0, 0, 0, 30, 0, time.UTC)
	duration := date.Sub(unixEpoch)

	days := int64(math.Floor(duration.Hours() / 24))
	return days
}

func HourSinceUnixEpoch(date time.Time) int64 {
	date = date.UTC()
	unixEpoch := time.Date(1970, time.January, 0, 0, 0, 30, 0, time.UTC)
	duration := date.Sub(unixEpoch)

	hours := int64(math.Floor(duration.Hours()))
	return hours
}

func UnixEpochAddDay(d int64) int64 {
	unixEpoch := time.Date(1970, time.January, 0, 0, 0, 30, 0, time.UTC)
	at := unixEpoch.Add(24 * time.Hour * time.Duration(d))
	return at.UnixMilli()
}

func UnixEpochAddHour(h int64) int64 {
	unixEpoch := time.Date(1970, time.January, 0, 0, 0, 30, 0, time.UTC)
	at := unixEpoch.Add(time.Hour * time.Duration(h))
	return at.UnixMilli()
}
