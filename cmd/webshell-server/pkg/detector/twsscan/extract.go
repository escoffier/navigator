package twsscan

// ExtractFile extracts a part of content
func ExtractFile(content []byte) []byte {
	var runes []rune
	var number = 0
	var s = BytesToString(content)

	for _, v := range s {

		if len(s)-number <= 20 {
			runes = append(runes, v)
			number++
			continue
		}

		if number <= 50 {
			runes = append(runes, v)
		} else if number <= 500 {
			if number%100 <= 4 {
				runes = append(runes, v)
			}
		} else if number <= 5000 {

			if number%1000 <= 4 {
				runes = append(runes, v)
			}
		} else if number <= 50000 {
			if number%3000 <= 4 {
				runes = append(runes, v)
			}
		}

		number++
	}

	return StringToBytes(string(runes))
}
