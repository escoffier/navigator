package tools

// Byte2Strings :[]bytes -> []string
func Byte2Strings(bytes [][]byte) []string {
	var s = make([]string, 0, len(bytes))

	for i := range bytes {
		s = append(s, string(bytes[i]))
	}

	return s
}
