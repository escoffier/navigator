package mozart

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"
)

func ConvertOutput2OutputMap(output string) map[string]string {
	m := make(map[string]string)
	quoteStart := strings.Index(output, "(")
	quoteCount := 0
	quoteEnd := strings.LastIndex(output, ")")
	for i := quoteStart + 1; i < len(output); i++ {
		if output[i] == '(' {
			quoteCount += 1
			continue
		}
		if output[i] == ')' {
			if quoteCount == 0 {
				quoteEnd = i
				break
			} else {
				quoteCount -= 1
			}
		}
	}
	if quoteCount != 0 || quoteCount == len(output) {
		return m
	}
	if quoteStart == -1 || quoteEnd == -1 || quoteStart+1 >= quoteEnd || quoteEnd+2 > len(output) {
		return m
	}
	timeEnd := strings.LastIndex(output[:quoteStart], ":")
	if timeEnd != -1 && timeEnd+2 < quoteStart {
		m["output_origin_time"] = output[14:timeEnd]
		m["output_origin_rule"] = output[timeEnd+2 : quoteStart-1]
	}

	dataS := output[quoteStart+1 : quoteEnd]
	data := strings.Split(dataS, ",")
	lastKey := ""
	stack := make([]string, 0)
	for i := range data {
		equalIndex := strings.Index(data[i], "=")
		if equalIndex == -1 {
			stack = append(stack, data[i])
			continue
		}
		kv := []string{data[i][:equalIndex], data[i][equalIndex+1:]}
		needContinue := false
		for j := range kv[0] {
			if !((kv[0][j] >= 48 && kv[0][j] <= 57) || (kv[0][j] >= 65 && kv[0][j] <= 90) || (kv[0][j] >= 97 && kv[0][j] <= 122)) &&
				(kv[0][j] != '_' && kv[0][j] != '-' && kv[0][j] != '.') {
				for k := range stack {
					m[lastKey] = m[lastKey] + stack[k]
				}
				m[lastKey] = m[lastKey] + data[i]
				stack = make([]string, 0)
				needContinue = true
				break
			}
		}
		if needContinue {
			continue
		}
		if len(stack) != 0 {
			value := ""
			for k := range stack {
				value = value + stack[k]
			}
			stack = make([]string, 0)
			m[lastKey] = m[lastKey] + value
		}

		m[kv[0]] = kv[1]
		lastKey = kv[0]
	}

	return m
}

func sha256Hash(bs []byte) string {
	m := sha256.New()
	m.Write(bs)
	sbs := m.Sum(nil)
	return fmt.Sprintf("%x", sbs)
}

// input: 1s, 2m, 3h
func sDurationToTimeDuration(sd string) (time.Duration, error) {
	var t time.Duration
	sCacheNum := sd[:len(sd)-1]
	cacheNum, err := strconv.Atoi(sCacheNum)
	if err != nil {
		err := errors.New("sd convert int fails")
		logging.Get().Error().Err(err).Interface("sDuration", sd).Msg(err.Error())
		return t, err
	}
	switch sd[len(sd)-1] {
	case 's':
		t = time.Second * time.Duration(cacheNum)
	case 'm':
		t = time.Minute * time.Duration(cacheNum)
	case 'h':
		t = time.Hour * time.Duration(cacheNum)
	default:
		err = errors.New("invalid duration key")
		logging.Get().Error().Err(err).Str("sDuration", sd).Msg("invalid duration key")
		return t, err
	}
	return t, nil
}
