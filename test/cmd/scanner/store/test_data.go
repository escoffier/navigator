package store

import (
	"context"
	"encoding/json"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/task"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

var (
	Host     = "localhost"
	Port     = "5432"
	Username = "postgres"
	Password = "password"
)

var defaultSubtask = model.SubTask{
	ID:      1,
	TaskId:  1,
	ImageId: 1,
	//RepoName: "nginx",
	//Tag:      "1.20",
	Status: 0,
	Result: 0,
}

var defaultTask = model.Task{
	ID:        1,
	ScopeType: consts.FullScan,
	Trigger:   consts.ManualTrigger,
	FlowConf:  "mock-flow",
	Status:    0,
	Result:    0,
}

func generateScanType() (string, error) {
	s := task.ScanConfig{
		Type:   "scan-vuln",
		Policy: "",
	}
	ss := make([]task.ScanConfig, 0)
	ss = append(ss, s)
	data, err := json.Marshal(&ss)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func InitDb() error {
	db, gormDb, err := NewPostgresDb(Host, Port, Username, Password)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("connect db err")
		return err
	} else {
		logging.GetLogger().Info().Msg("connect db ok")
	}

	// migrate for test
	err = gormDb.AutoMigrate(&model.Task{}, &model.SubTask{})
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("auto migrate failed")
		return err
	}

	// insert test data
	st := defaultSubtask
	t := defaultTask
	//scanType, err := generateScanType()
	//if err != nil {
	//	logging.GetLogger().Error().Err(err).Msg("make scan type failed")
	//	return err
	//}
	//t.ScanType = scanType

	_, err = db.InsertTask(context.Background(), t)
	if err != nil {
		logging.GetLogger().Err(err).Msg("inert task failed")
		return err
	}
	_, err = db.InsertSubTask(context.Background(), st)
	if err != nil {
		logging.GetLogger().Err(err).Msg("inert subtask failed")
		return err
	}
	return nil
}
