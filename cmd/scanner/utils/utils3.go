package scannerUtils

import (
	"math"
	"regexp"
	"sync"
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
