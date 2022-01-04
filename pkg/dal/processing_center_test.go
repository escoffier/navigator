package dal

import (
	"context"
	"testing"
	"time"

	"github.com/olivere/elastic/v7"
	"github.com/stretchr/testify/assert"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func initProcessingCenterDB(t *testing.T) {
	initDB(t)
}

func TestSaveProcessingAction(t *testing.T) {
	initProcessingCenterDB(t)
	action := &model.ProcessingAction{
		RecordID:  "testID",
		Operation: "testOperation",
		Creator:   "testUser",
		CreatedAt: time.Now(),
	}
	action.SetObject([]string{"cluster@namespace@pod1", "cluster@namespace@pod2"})
	err := SaveProcessingAction(context.TODO(), db, action)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGetProcessingActions(t *testing.T) {
	initProcessingCenterDB(t)
	actions, err := GetProcessingActions(context.TODO(), db, "testID")
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range actions {
		t.Log(action)
	}
}

func TestSaveProcessingRecord(t *testing.T) {
	esCli, err := elastic.NewClient(elastic.SetSniff(false))
	if err != nil {
		t.Fatal(err)
	}
	id := util.GenerateUUIDHex()
	t.Log(id)
	err = SaveProcessingRecord(context.TODO(), esCli, "processing_record_test", &model.ProcessingRecord{
		ID:         id,
		EventID:    101,
		OpType:     "test",
		UpdatedAt:  util.GetMillisecondTimestampByTime(time.Now()),
		Status:     "test",
		LastOpUser: "test",
		Object:     []string{"cluster@namespace@pod1", "cluster@namespace@pod2"},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestUpdateProcessingRecord(t *testing.T) {
	esCli, err := elastic.NewClient(elastic.SetSniff(false))
	if err != nil {
		t.Fatal(err)
	}
	err = UpdateProcessingRecord(context.TODO(), esCli, "processing_record_test", &model.ProcessingRecordChange{
		ID:         "4f5d7023a0a1445faa6d292235841a00",
		LastOpUser: "updateUser",
		Status:     "updateStatus",
		UpdatedAt:  util.GetMillisecondTimestampByTime(time.Now()),
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestQueryProcessingRecordByID(t *testing.T) {
	esCli, err := elastic.NewClient(elastic.SetSniff(false))
	if err != nil {
		t.Fatal(err)
	}
	record, err := QueryProcessingRecordByID(context.TODO(), esCli, "processing_record_test", "4f5d7023a0a1445faa6d292235841a00")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(record)

	_, err = QueryProcessingRecordByID(context.TODO(), esCli, "processing_record_test", "nonsense")
	assert.Equal(t, ErrNotFound, err)
}

func TestQueryProcessingRecord(t *testing.T) {
	esCli, err := elastic.NewClient(elastic.SetSniff(false))
	if err != nil {
		t.Fatal(err)
	}

	total, records, err := QueryProcessingRecord(context.TODO(), esCli, "processing_record_test", &model.QueryProcessingRecordArg{Limit: 20})
	if err != nil {
		t.Fatal(err)
	}

	t.Log(total, records)
}
