package pkg

import "strings"

func ImageReTag(old, new string) string {
	index := strings.Index(old, "/")
	return new + "/" + old[index+1:]
}
