package util

func StringSetToArray(hash map[string]struct{}) []string {
	var result = make([]string, 0, len(hash))
	for str := range hash {
		result = append(result, str)
	}

	return result
}

func FilterDuplicateIntArray(arr []int) []int {
	hash := make(map[int]struct{})
	for _, v := range arr {
		hash[v] = struct{}{}
	}
	if len(hash) == len(arr) {
		return arr
	}

	result := make([]int, 0, len(hash))
	for v := range hash {
		result = append(result, v)
	}

	return result
}
