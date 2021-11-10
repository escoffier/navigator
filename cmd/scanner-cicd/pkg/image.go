package pkg

import "strings"

func ImageReTag(old, new string) string {
	index := strings.Index(old, "/")
	newTag := new + "/" + old[index+1:]
	newTag = strings.Replace(newTag, "https://", "", 1)
	newTag = strings.Replace(newTag, "http://", "", 1)
	return newTag
}
