package re

import (
	"regexp"
)

type Regexes []*regexp.Regexp

func (r Regexes) Scan(content []byte) [][]byte {
	var contents [][]byte

	for _, v := range r {
		e := v.FindAll(content, -1)
		for j := range e {
			if len(e[j]) > 0 {
				contents = append(contents, e[j])
			}
		}
	}

	return contents
}
