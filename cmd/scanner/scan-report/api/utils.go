package api

import (
	"strings"
)

func GetFilename(file string) string {
	if file == "" {
		return file
	}
	split := strings.Split(file, "/")

	if len(split) > 0 {
		return split[len(split)-1]
	}
	return file
}
