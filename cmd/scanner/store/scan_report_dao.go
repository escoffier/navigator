package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	scanreport "gitlab.com/piccolo_su/vegeta/pkg/model/scan-report"
	"gitlab.com/piccolo_su/vegeta/pkg/util"

	"github.com/pkg/errors"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var (
	// NotCurrentTimeError 把tensor_scan_report的current_time_seq改成当月或者当周时，没有数据修改时返回的错误
	NotCurrentTimeError = errors.New("NotCurrentTime")
)

type ScanReportInterface interface {
	// ScanReportCreate 创建一个扫描报告
	ScanReportCreate(ctx context.Context, task *scanreport.TensorScanReportTasks) (uint, error)

	// ScanReportUpdate 更新一个扫描报告
	ScanReportUpdate(ctx context.Context, task *scanreport.TensorScanReportTasks) error

	// ScanReportDelete 删除一个扫描报告
	ScanReportDelete(ctx context.Context, id uint) error

	// ScanReportList 扫描报告列表
	ScanReportList(ctx context.Context, query string, limit, offset int, _type []uint8) ([]scanreport.TensorScanReportTasks, int64, error)

	// ScanReportDetail 获取报告详情
	ScanReportDetail(ctx context.Context, id uint) (*scanreport.TensorScanReportTasks, error)

	// ScanReportFilesList 获取任务对应文件列表
	ScanReportFilesList(ctx context.Context, scanReportId uint, limit, offset int) ([]scanreport.TensorScanReportSubTasks, int64, error)

	// GetCurrentSubTask 获取可以执行的子任务
	GetCurrentSubTask(ctx context.Context, now time.Time) ([]*scanreport.TensorScanReportSubTasks, error)

	// UpdateSubTaskStatus 修改current_time_seq字段为当前时间,来标识本次任务正在执行，通过数据库来达到避免数据被多次执行
	UpdateSubTaskStatus(ctx context.Context, id uint, status scanreport.SubTasksStatus) error

	// GetImagesByTask 通过task构建查询条件，然后获取Image的信息
	GetImagesByTask(ctx context.Context, limit, offset int, task *scanreport.TensorScanReportSubTasks) ([]*scanreport.ImageInfo, error)

	// ScanReportDownload 下载报告文件
	ScanReportDownload(ctx context.Context, taskId, fileId uint) (*scanreport.TensorScanReportSubTasks, error)

	// UpdateSubTaskStatusWithRunning 标记子任务为 running 状态，并且在为周报或者月报时还会创建下一个周期的任务
	UpdateSubTaskStatusWithRunning(ctx context.Context, subtask *scanreport.TensorScanReportSubTasks) error

	// SaveScanReportFile 保存报告结果文件，并且修改为success状态，同时修改task的last_time字段
	SaveScanReportFile(ctx context.Context, subtask *scanreport.TensorScanReportSubTasks, file []byte) error

	// ScanReportSubTaskCreate 创建一个扫描报告的子任务
	ScanReportSubTaskCreate(ctx context.Context, task *scanreport.TensorScanReportSubTasks) (uint, error)
}

func (s *ScannerOrm) ScanReportCreate(ctx context.Context, task *scanreport.TensorScanReportTasks) (uint, error) {
	subtask := task.GenSubtask()

	err := s.psql.Get().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(task).Error; err != nil {
			return errors.Wrap(err, "crate scan report task failed")
		}

		subtask.ScanReportId = task.ID

		if err := tx.Create(subtask).Error; err != nil {
			return errors.Wrap(err, "crate scan report subtask failed")
		}
		return nil
	})

	return task.ID, err
}

func (s *ScannerOrm) ScanReportUpdate(ctx context.Context, task *scanreport.TensorScanReportTasks) error {
	subtask := task.GenSubtask()

	err := s.psql.Get().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// 更新task
		res := tx.
			Select("*").
			Omit("type", "created_at", "deleted_at", "id"). // type,created_at,deleted_at字段不能被更新 不能被更新
			Where("id = ?", task.ID).
			Where("type != ?", scanreport.TensorScanReportTypeCustomize).
			Updates(task)

		err := res.Error
		if err != nil {
			return errors.Wrap(err, "update scan report task failed")
		}

		if res.RowsAffected == 0 {
			return fmt.Errorf("update failed, not recode to update, id: %d, name: %s", task.ID, task.Name)
		}

		// 将现存的处于waiting 和 failed 状态的subtask取消
		tx1 := tx.
			Model(scanreport.TensorScanReportSubTasks{}).
			Where("scan_report_id = ?", task.ID).
			Where("status IN (?)", []scanreport.SubTasksStatus{scanreport.SubTasksStatusWaiting, scanreport.SubTasksStatusFailed}).
			Update("status", scanreport.SubTasksStatusCancel)

		if err := tx1.Error; err != nil {

			return errors.Wrap(err, "cancel scan report subtask  failed")
		}

		subtask.ScanReportId = task.ID

		err = tx.
			Clauses(clause.OnConflict{
				Columns: []clause.Column{{Name: "scan_report_id"}, {Name: "end_timestamp"}},
				DoUpdates: clause.Assignments(map[string]interface{}{
					"status": gorm.Expr( // 当出现唯一键冲突时，把状态为waiting,failed,cancel的改为waiting,其他状态不变
						"CASE tensor_scan_report_sub_tasks.status WHEN ? THEN ? WHEN ? THEN ? WHEN ? THEN ? else tensor_scan_report_sub_tasks.status end",
						scanreport.SubTasksStatusWaiting, scanreport.SubTasksStatusWaiting, scanreport.SubTasksStatusFailed,
						scanreport.SubTasksStatusWaiting, scanreport.SubTasksStatusCancel, scanreport.SubTasksStatusWaiting,
					)},
				),
			}).Create(subtask).Error
		if err != nil {
			return errors.Wrap(err, "crate or update scan report subtask failed")
		}
		return nil
	})

	return err
}

func (s *ScannerOrm) ScanReportDelete(ctx context.Context, id uint) error {

	err := s.psql.Get().WithContext(ctx).Transaction(

		func(tx *gorm.DB) error {
			// 删除任务
			err := tx.Delete(&scanreport.TensorScanReportTasks{}, id).Error
			if err != nil {
				return errors.Wrap(err, "删除任务失败")
			}

			// 将waiting和failed的子任务取消了
			err = tx.Model(scanreport.TensorScanReportSubTasks{}).
				Where("scan_report_id = ?", id).
				Where("status IN (?)", []scanreport.SubTasksStatus{scanreport.SubTasksStatusWaiting, scanreport.SubTasksStatusFailed}).
				Update("status", scanreport.SubTasksStatusCancel).
				Error
			if err != nil {
				return errors.Wrap(err, "取消子任务失败")
			}

			return nil
		},
	)

	return err
}

func (s *ScannerOrm) ScanReportList(ctx context.Context, query string, limit, offset int, _type []uint8) ([]scanreport.TensorScanReportTasks, int64, error) {
	db := s.psql.Get().WithContext(ctx).Model(scanreport.TensorScanReportTasks{})
	if query != "" {
		db = db.Where("name LIKE @query OR emails::TEXT LIKE @query", sql.Named("query", "%"+query+"%")) // fix don't use jsonb
	}

	if len(_type) > 0 {
		db = db.Where("type IN (?)", _type)
	}

	var count int64
	var data = make([]scanreport.TensorScanReportTasks, 0, limit)

	if err := db.Count(&count).Error; err != nil {
		return nil, 0, err
	}

	err := db.
		Order(clause.OrderByColumn{Column: clause.Column{Name: "id"}, Desc: true}).
		Limit(limit).
		Offset(offset).
		Find(&data).
		Error
	if err != nil {
		return nil, 0, err
	}

	return data, count, nil
}

func (s *ScannerOrm) ScanReportDetail(ctx context.Context, id uint) (*scanreport.TensorScanReportTasks, error) {
	var data = new(scanreport.TensorScanReportTasks)

	err := s.psql.Get().
		WithContext(ctx).
		Model(data).
		Where("id = ?", id).
		First(data).
		Error

	if err != nil {
		return nil, err
	}

	return data, nil
}

func (s *ScannerOrm) ScanReportFilesList(ctx context.Context, scanReportId uint, limit, offset int) ([]scanreport.TensorScanReportSubTasks, int64, error) {
	db := s.psql.Get().
		WithContext(ctx).
		Model(scanreport.TensorScanReportSubTasks{}).
		Where("scan_report_id = ?", scanReportId).
		Where("status = ?", scanreport.SubTasksStatusSucceeded)

	var count int64

	if err := db.Count(&count).Error; err != nil {
		return nil, 0, err
	}

	var data = make([]scanreport.TensorScanReportSubTasks, 0, limit)

	err := db.
		Order(clause.OrderByColumn{Column: clause.Column{Name: "id"}, Desc: true}).
		Limit(limit).
		Offset(offset).
		Order(clause.OrderByColumn{Column: clause.Column{Name: "end_timestamp"}, Desc: true}).
		Find(&data).
		Error
	if err != nil {
		return nil, 0, err
	}

	return data, count, nil
}

// GetCurrentSubTask 获取可以执行的子任务
func (s *ScannerOrm) GetCurrentSubTask(ctx context.Context, now time.Time) ([]*scanreport.TensorScanReportSubTasks, error) {
	var (
		data []*scanreport.TensorScanReportSubTasks
		err  error
	)
	err = s.psql.Get().
		WithContext(ctx).
		Model(scanreport.TensorScanReportSubTasks{}).
		Preload("TensorScanReportTasks").
		Where("status IN (?)", []uint8{uint8(scanreport.SubTasksStatusWaiting), uint8(scanreport.SubTasksStatusFailed)}).
		Where("end_timestamp < ?", now.Unix()*1000).
		Where("failed_count < ?", 3). // 失败3次以上不再重试
		Find(&data).Error

	if err != nil {
		return nil, err
	}

	return data, nil
}

func (s *ScannerOrm) UpdateSubTaskStatus(ctx context.Context, id uint, status scanreport.SubTasksStatus) error {
	// 更新状态的前置状态
	var preStatus []scanreport.SubTasksStatus
	var updateFiled = map[string]interface{}{"status": status}
	switch status {
	case scanreport.SubTasksStatusWaiting:
		return errors.New("can't be status: waiting")
	case scanreport.SubTasksStatusRunning:
		preStatus = []scanreport.SubTasksStatus{scanreport.SubTasksStatusWaiting, scanreport.SubTasksStatusFailed}
	case scanreport.SubTasksStatusFailed:
		updateFiled["failed_count"] = gorm.Expr("failed_count+1")
		fallthrough
	case scanreport.SubTasksStatusSucceeded:
		preStatus = []scanreport.SubTasksStatus{scanreport.SubTasksStatusRunning}
	}

	db := s.psql.Get().WithContext(ctx).Model(scanreport.TensorScanReportSubTasks{}).Where("id = ?", id)

	if len(preStatus) > 0 {
		db = db.Where("status IN (?)", preStatus)

	}
	db = db.Updates(updateFiled)

	if err := db.Error; err != nil {
		return err
	}

	if db.RowsAffected == 0 {
		return NotCurrentTimeError
	}

	return nil
}

func (s *ScannerOrm) GetImagesByTask(ctx context.Context, limit, offset int, task *scanreport.TensorScanReportSubTasks) ([]*scanreport.ImageInfo, error) {
	var selectFiled = []string{
		"t.id",
		"t.library", "t.full_repo_name", "t.tags", "t.privileged_boot", "t.is_reinforce",

		"s.risk_score", "s.vuln_score", "s.has_fixed_vuln", "s.sensitive_score", "s.virus_score",
		"s.webshell_info_json", "s.vuln_info_json", "s.scan_enable_collection_json",
		"s.malicious_info_json", "s.license_info_json", "s.software_json",
		"s.sensitive_file_json",

		"ti.is_trusted",
		"tc.image_uuid as imageuuid",
	}

	db := s.psql.Get().
		WithContext(ctx).
		Table("tensor_image_list AS t").
		Order(clause.OrderByColumn{Column: clause.Column{Name: "t.id"}}).
		Limit(limit).
		Offset(offset).
		Select(selectFiled).
		//Where("t.updated_at >= ? AND t.updated_at < ?", time.Unix(task.StartTimeStamp, 0), time.Unix(task.EndTimeStamp, 0)).
		Joins("LEFT JOIN scan_images AS s ON t.id = s.image_id").
		Joins("LEFT JOIN trusted_images AS ti ON t.digest = ti.digest").
		Joins("LEFT JOIN (SELECT DISTINCT image_uuid FROM tensor_containers) as tc ON t.image_uuid = tc.image_uuid AND t.from_type != 2")

	{ //报告对象
		var db1, db2 *gorm.DB

		if task.TensorScanReportTasks.ImageTypeEnum&scanreport.TensorScanReportImageTypeRegistry == scanreport.TensorScanReportImageTypeRegistry {

			switch task.TensorScanReportTasks.RegistryImageType {
			case scanreport.TensorScanReportRegistryImageTypeProject: // 项目
				db1 = s.psql.Get().Where("project IN ?", task.TensorScanReportTasks.RegistryImageObjects)
			case scanreport.TensorScanReportRegistryImageTypeRegistry: // 仓库
				db1 = s.psql.Get().
					Where(
						"registry_id IN (?)",
						s.psql.Get().Model(model.Registry{}).Select("id").
							Where("name IN ?", task.TensorScanReportTasks.RegistryImageObjects).
							Where("deleted_at = ?", 0),
					)
			case scanreport.TensorScanReportRegistryImageTypeProjectAndRegistry: // 项目仓库
				var project = make([]string, 0, len(task.TensorScanReportTasks.RegistryImageObjects))
				var registies = make([]string, 0, len(task.TensorScanReportTasks.RegistryImageObjects))
				for _, v := range task.TensorScanReportTasks.RegistryImageObjects {
					s := strings.Split(v, " ")
					if len(s) == 2 {
						project = append(project, s[0])
						registies = append(registies, s[1])
					}
				}

				db1 = s.psql.Get().Where("project IN ?", project)

				db1 = db1.
					Where(
						"registry_id IN (?)",
						s.psql.Get().Model(model.Registry{}).Select("id").
							Where("name IN ?", registies),
					)
			}

			db1 = db1.Where("t.from_type = ?", model.ImageFromTypeNormal)
		}

		if task.TensorScanReportTasks.ImageTypeEnum&scanreport.TensorScanReportImageTypeNode == scanreport.TensorScanReportImageTypeNode {
			db2 = s.psql.Get().
				Where(
					"node_hostname IN (?)",
					s.psql.Get().Model(model.PodResourceRelation{}).
						Distinct("node_name").
						Where("cluster_key IN ?", task.TensorScanReportTasks.NodeImageObjects),
				).
				Where("t.from_type = ?", model.ImageFromSafeNode)
		}

		if db1 != nil && db2 != nil {
			db = db.Where(s.psql.Get().Where(db1).Or(db2))
		} else if db1 != nil && db2 == nil {
			db = db.Where(db1)
		} else if db1 == nil && db2 != nil {
			db = db.Where(db2)
		} else {
			return nil, errors.New("unknown image object type")
		}
	}

	var data = make([]*scanreport.ImageInfo, 0, limit)
	err := db.Find(&data).Error
	if err != nil {
		return nil, err
	}

	return data, nil
}

func (s *ScannerOrm) ScanReportDownload(ctx context.Context, taskId, fileId uint) (*scanreport.TensorScanReportSubTasks, error) {
	var data scanreport.TensorScanReportSubTasks
	err := s.psql.Get().
		WithContext(ctx).
		Model(&data).
		Where("id = ?", fileId).
		Where("scan_report_id = ?", taskId).
		Where("status = ?", scanreport.SubTasksStatusSucceeded).
		First(&data).
		Error
	if err != nil {
		return nil, err
	}

	return &data, nil
}

func (s *ScannerOrm) UpdateSubTaskStatusWithRunning(ctx context.Context, subtask *scanreport.TensorScanReportSubTasks) error {
	var data scanreport.TensorScanReportSubTasks

	var nextSubTask scanreport.TensorScanReportSubTasks

	// 当是周期任务时，需要生成下一个周期的任务
	if subtask.Type == scanreport.SubTaskTypeCircle {
		nextSubTask = scanreport.TensorScanReportSubTasks{
			ScanReportId: subtask.ScanReportId,
			Status:       scanreport.SubTasksStatusWaiting,
			Type:         scanreport.SubTaskTypeCircle,
		}

		if subtask.TensorScanReportTasks.Type == scanreport.TensorScanReportTypeWeek {
			nextSubTask.StartTimeStamp = subtask.EndTimeStamp
			nextSubTask.EndTimeStamp = subtask.EndTimeStamp + 7*24*60*60*1000
		} else if subtask.TensorScanReportTasks.Type == scanreport.TensorScanReportTypeMonth {
			nextSubTask.StartTimeStamp = subtask.EndTimeStamp

			nextSubTask.EndTimeStamp = time.Unix(0, subtask.EndTimeStamp*int64(time.Millisecond)).
				AddDate(0, 1, 0).In(util.CSTSh).Unix() * 1000
		}
	}

	err := s.psql.Get().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		db := tx.Model(&data).
			Where("id = ?", subtask.ID).
			Where("scan_report_id = ?", subtask.ScanReportId).
			Where("status IN (?)", []scanreport.SubTasksStatus{scanreport.SubTasksStatusWaiting, scanreport.SubTasksStatusFailed}).
			Update("status", scanreport.SubTasksStatusRunning)

		if err := db.Error; err != nil {
			return errors.Wrap(err, "update subtask's status to running failed")
		}

		if db.RowsAffected == 0 {
			return NotCurrentTimeError
		}

		// 当是周期任务时，需要生成下一个周期的任务，这里创建下个周期的任务
		if subtask.Type == scanreport.SubTaskTypeCircle {
			if err := tx.
				Clauses(
					clause.OnConflict{
						DoNothing: true,
						Columns:   []clause.Column{{Name: "scan_report_id"}, {Name: "end_timestamp"}},
					},
				).
				Create(&nextSubTask).
				Error; err != nil {
				return errors.Wrap(err, "create next circle task failed")
			}
		}

		return nil
	})

	return err
}

func (s *ScannerOrm) SaveScanReportFile(ctx context.Context, subtask *scanreport.TensorScanReportSubTasks, file []byte) error {
	err := s.psql.Get().WithContext(ctx).Transaction(
		func(tx *gorm.DB) error {
			// 保存文件，更新状态
			db := tx.
				Model(subtask).
				Where("id = ?", subtask.ID).
				Where("status = ?", scanreport.SubTasksStatusRunning).
				Updates(map[string]interface{}{"status": scanreport.SubTasksStatusSucceeded, "file": file})

			if err := db.Error; err != nil {
				return errors.Wrap(err, "保存文件失败")
			}

			if db.RowsAffected == 0 {
				return NotCurrentTimeError
			}

			// 修改last_time
			err := tx.
				Model(&scanreport.TensorScanReportTasks{}).
				Where("id = ?", subtask.ScanReportId).
				Update("last_timestamp", time.Now().In(util.CSTSh).Unix()*1000).
				Error

			if err != nil {
				return errors.Wrap(err, "更新任务最近时间失败")
			}

			return nil
		},
	)

	return err
}

func (s *ScannerOrm) ScanReportSubTaskCreate(ctx context.Context, subtask *scanreport.TensorScanReportSubTasks) (uint, error) {
	if err := s.psql.Get().WithContext(ctx).Create(subtask).Error; err != nil {
		return 0, err
	}

	return subtask.ID, nil
}
