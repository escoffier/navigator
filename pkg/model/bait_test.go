package model

// func TestUpsertBait(t *testing.T) {
// 	rdb, mock, _ := mockGorm()
// 	mock.ExpectBegin()
// 	mock.ExpectExec("^INSERT").WillReturnResult(sqlmock.NewResult(1, 1))
// 	mock.ExpectCommit()
// 	//mock.ExpectExec("^INSERT").WillReturnError(nil)
// 	//db.GetReadDB().DryRun = true

// 	var onDupUpdatedColsForBait = []string{
// 		"name",
// 		"bait_name",
// 		"image",
// 	}

// 	bs := &BaitService{
// 		TableBase:      TableBase{},
// 		Name:           "",
// 		BaitName:       "test",
// 		BaitId:         0,
// 		ClusterKey:     "",
// 		Namespace:      "",
// 		ResourceName:   "",
// 		Prefix:         "",
// 		Image:          "",
// 		RegistryId:     0,
// 		WorkLoadStatus: "",
// 		HaveAlerts:     false,
// 		Replica:        0,
// 		OutboundOff:    false,
// 	}
// 	rdb.Get().Model(&BaitService{}).Clauses(clause.OnConflict{
// 		Columns:   []clause.Column{{Name: "id"}},
// 		DoUpdates: clause.AssignmentColumns(onDupUpdatedColsForBait),
// 	}).Create(bs)
// }
