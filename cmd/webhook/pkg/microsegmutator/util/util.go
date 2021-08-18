package util

import (
	"fmt"
	"github.com/pkg/errors"
	"hash/fnv"
	"regexp"
	"strings"
)

func GenID(strs ...string) uint32 {
	s := strings.Join(strs, ",")
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return h.Sum32()
}

func ValidatePathParam(strs ...string) error {
	for _, s := range strs {
		if s == "" {
			return errors.New("missing path param")
		}
	}
	return nil
}

func EnsureValidK8sLabel(label string) error {
	K8sLabelRegex := regexp.MustCompile("(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?")
	submatches := K8sLabelRegex.FindAllStringSubmatch(label, -1)
	if len(submatches) != 1 {
		return fmt.Errorf("%s is invalid (must consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character)", label)
	}
	if len(label) > 63 {
		return fmt.Errorf("%s is invalid (max length is 63 characters)", label)
	}

	return nil
}

//func PGMigrate(dsn string, models ...interface{}) {
//	db, err := gorm.Open(postgres.New(postgres.Config{
//		DSN: dsn,
//	}), &gorm.Config{})
//	if err != nil {
//		logrus.Error(err)
//		return
//	}
//	db.DryRun = true
//	db.Logger = New(logger.Config{
//		SlowThreshold: 200 * time.Millisecond,
//		LogLevel:      logger.Info,
//	})
//	err = db.Debug().Migrator().CreateTable(models...)
//	if err != nil {
//		logrus.Error(err)
//	}
//
//}
