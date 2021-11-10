package reporter

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func TestLoadEventsReport(t *testing.T) {
	postgresqlDSN := fmt.Sprintf("host=%s user=%s dbname=%s sslmode=%s password=%s",
		"localhost", "pguser", "tensorsecurity", "disable", "pgpassword")
	db, err := rdbtools.NewPostgresClient(postgresqlDSN)
	if err != nil {
		t.Fatal(err)
	}

	clusterHash := map[string]string{
		"testCluster": "test-cluster",
	}

	eventReport := LoadEventsReport(context.TODO(), db, 0, util.GetMillisecondTimestampByTime(time.Now()), clusterHash)
	jsonBytes, err := json.Marshal(eventReport)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(util.Bytes2StringNoCopy(jsonBytes))
}
