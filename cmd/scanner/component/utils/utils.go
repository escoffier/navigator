package utils

import (
	"encoding/json"
	"io"
	"os"
)

type Sensitive struct {
	Description string `json:"description"`
	SecretType  string `json:"secret_type"`
	Value       string `json:"value"`
}

func GetSensitiveRuleFromFile(path string) ([]Sensitive, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	data := make([]Sensitive, 0)

	byteValue, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(byteValue, &data)
	if err != nil {
		return nil, err
	}
	return data, nil
}
