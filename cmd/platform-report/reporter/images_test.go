package reporter

import (
	"context"
	"fmt"
	"testing"

	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
)

func TestGetOnlineImageUUIDList(t *testing.T) {
	postgresqlDSN := fmt.Sprintf("host=%s user=%s dbname=%s sslmode=%s password=%s",
		"localhost", "pguser", "tensorsecurity", "disable", "pgpassword")
	db, err := rdbtools.NewPostgresClient(postgresqlDSN)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(getOnlineImageUUIDList(context.TODO(), db))
}

func TestGetImageName(t *testing.T) {
	library := "https://quay.io"
	fullName := "tensorsecurity/baseimage-drift-prevention"
	t.Log(getImageName(library, fullName))

	library = "nonsense"
	t.Log(getImageName(library, fullName))
}
