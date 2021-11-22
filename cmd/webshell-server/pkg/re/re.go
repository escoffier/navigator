package re

import (
	"regexp"
	"unicode/utf8"
)

type Regexes []*regexp.Regexp

func (r Regexes) Scan(content []byte) [][]byte {
	var contents [][]byte

	for _, v := range r {
		e := v.FindAll(content, -1)
		for j := range e {
			// 这里只保存合法的utf8编码的字符串
			if len(e[j]) > 0 && utf8.Valid(e[j]) {
				contents = append(contents, e[j])
			}
		}
	}

	return contents
}
