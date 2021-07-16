package util

func StringSetToArray(hash map[string]struct{}) []string {
	var result = make([]string, 0, len(hash))
	for str := range hash {
		result = append(result, str)
	}

	return result
}
