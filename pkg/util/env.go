package util

import (
	"os"
	"strconv"
)

const (
	EnvKeyTestNonSingletonPod = "ENV_TEST_NON_SINGLETON"
)

var (
	testNonSingletonPod = false
)

func init() {
	val := os.Getenv(EnvKeyTestNonSingletonPod)
	if val == "" {
		return
	}
	bl, err := strconv.ParseBool(val)
	if err == nil && bl {
		testNonSingletonPod = true
	}
}

func IsNonSingletonPodInTestingEnv() bool {
	return testNonSingletonPod
}

func GetEnvWithDefault(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func GetIntValWithDefault(key string, fallback int) int {
	if str, ok := os.LookupEnv(key); ok {
		value, err := strconv.Atoi(str)
		if err == nil {
			return value
		}
	}

	return fallback
}

func GetBoolValWithDefault(key string, fallback bool) bool {
	if str, ok := os.LookupEnv(key); ok {
		return str == "true"
	}

	return fallback
}
