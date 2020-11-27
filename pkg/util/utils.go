package util

import (
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"

	"github.com/golang/gddo/httputil/header"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

func SortOrderToInt(sortOrder string) int {
	if sortOrder == "asc" {
		return 1
	} else if sortOrder == "desc" {
		return -1
	}
	logging.GetLogger().Warn().Str("sortOrder", sortOrder).Msg("Unknown sortOrder string, can be asc/desc.")
	return 1
}

func DecodeJSONBody(w http.ResponseWriter, r *http.Request, dst interface{}) error {
	if reflect.ValueOf(dst).Kind() != reflect.Ptr {
		return errors.New("Expected dst to be pointer")
	}

	if r.Header.Get("Content-Type") != "" {
		value, _ := header.ParseValueAndParams(r.Header, "Content-Type")
		if value != "application/json" {
			return errors.New("The http header is not application/json")
		}
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1048576)

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	err := dec.Decode(&dst)
	if err != nil {
		return err
	}

	if dec.More() {
		return errors.New("Request body must only contain a single JSON object")
	}

	return nil
}

func AppendIfMissing(s []string, i string) []string {
	for _, ele := range s {
		if ele == i {
			return s
		}
	}
	return append(s, i)
}

func ContainsString(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func RemoveScoredNotScoredFrom(thing string) string {
	thing = strings.ReplaceAll(thing, " (Not Scored)", "")
	thing = strings.ReplaceAll(thing, " ( Not Scored)", "")
	thing = strings.ReplaceAll(thing, " (Scored)", "")
	return thing
}
