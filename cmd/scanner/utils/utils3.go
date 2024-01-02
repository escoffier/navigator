package scannerUtils

import (
	"archive/zip"
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/cmd/global"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
)

var (
	reControlCharsRegex = regexp.MustCompile("[\u0000-\u001f\u0080-\u009f]")
	reRelativePathRegex = regexp.MustCompile(`^\.+`)

	// https://github.com/sindresorhus/filename-reserved-regex/blob/master/index.js
	filenameReservedRegex             = regexp.MustCompile(`[<>:"/\\|?*\x00-\x1F]`)
	filenameReservedWindowsNamesRegex = regexp.MustCompile(`(?i)^(con|prn|aux|nul|com[0-9]|lpt[0-9])$`)
)

func Filename(str string) string {

	replacement := "_"

	maxLength := 1000

	// reserved word
	str = filenameReservedRegex.ReplaceAllString(str, replacement)

	// continue
	str = reControlCharsRegex.ReplaceAllString(str, replacement)
	str = reRelativePathRegex.ReplaceAllString(str, replacement)

	// for repeat
	str = trimRepeated(str, replacement)

	if len(str) > 1 {
		str = stripOuter(str, replacement)
	}

	// for windows names
	if filenameReservedWindowsNamesRegex.MatchString(str) {
		str = str + replacement
	}

	// limit length
	strBuf := []rune(str)
	strBuf = strBuf[0:int(math.Min(float64(maxLength), float64(len(strBuf))))]

	return string(strBuf)
}

// https://github.com/sindresorhus/escape-string-regexp/blob/master/index.js
var reg = regexp.MustCompile(`[|\\{}()[\]^$+*?.-]`)

func escapeStringRegexp(str string) string {
	str = reg.ReplaceAllStringFunc(str, func(s string) string {
		return `\` + s
	})
	return str
}

type expressionCache struct {
	sync.RWMutex
	exp map[string]*regexp.Regexp
}

func (e *expressionCache) Get(exp string) *regexp.Regexp {
	e.RLock()
	v, ok := e.exp[exp]
	e.RUnlock()
	if ok {
		return v
	}
	e.Lock()
	defer e.Unlock()
	v = regexp.MustCompile(exp)
	e.exp[exp] = v
	return v
}

var cache = expressionCache{exp: make(map[string]*regexp.Regexp)}

func trimRepeated(str string, replacement string) string {
	exp := `(?:` + escapeStringRegexp(replacement) + `){2,}`
	reg := cache.Get(exp)
	return reg.ReplaceAllString(str, replacement)
}

func stripOuter(input string, substring string) string {
	// https://github.com/sindresorhus/strip-outer/blob/master/index.js
	substring = escapeStringRegexp(substring)
	exp := `^` + substring + `|` + substring + `$`
	reg := cache.Get(exp)
	return reg.ReplaceAllString(input, "")
}

type ZipFileMate struct {
	MD5      string `json:"md5"`
	Filename string `json:"filename"`
	Data     []byte
}

func ZipFile(wb ZipFileMate) ([]byte, error) {

	filename := filepath.Join(global.ScannerOpts.PvcPath, consts.WebshellFileDir, wb.MD5)

	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	b := new(bytes.Buffer)
	zw := zip.NewWriter(b)

	hdr := zip.FileHeader{Name: wb.Filename}
	w, err := zw.CreateHeader(&hdr)
	if err != nil {
		return nil, err
	}

	reader := bytes.NewReader(content)
	_, err = io.Copy(w, reader)
	if err != nil {
		return nil, err
	}
	if err := zw.Flush(); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

func ZipLicenseFile(wb ZipFileMate) ([]byte, error) {

	b := new(bytes.Buffer)
	zw := zip.NewWriter(b)

	hdr := zip.FileHeader{Name: wb.Filename}
	w, err := zw.CreateHeader(&hdr)
	if err != nil {
		return nil, err
	}

	reader := bytes.NewReader(wb.Data)
	_, err = io.Copy(w, reader)
	if err != nil {
		return nil, err
	}
	if err := zw.Flush(); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

func GenDigest(dig string) string {
	if strings.Contains(dig, "sha256:") {
		return dig
	}
	return fmt.Sprintf("sha256:%s", dig)
}

func GetSimDigest(di string) string {
	return strings.ReplaceAll(di, "sha256:", "")
}

func GetFileMd5(fi string) string {

	// 打开文件
	f, err := os.Open(fi)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()

	// 计算 MD5 值
	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	md5Str := hex.EncodeToString(h.Sum(nil))
	return md5Str
}

func GetContentMd5(data []byte) string {
	hash := md5.Sum(data)
	md5String := hex.EncodeToString(hash[:])
	return md5String
}

func GetFileContent(fi string) ([]byte, error) {
	content, err := os.ReadFile(fi)
	if err != nil {
		return nil, err
	}
	return content, nil
}
