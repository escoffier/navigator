package common

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/xuri/excelize/v2"
	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type UpdateExportTask interface {
	Start(ctx context.Context, id int64) error
	Success(ctx context.Context, id int64, filePath string) error
	Failure(ctx context.Context, id int64, msg string) error
	IncrRedisFinished(ctx context.Context, task model.ExportTensorTask) error
	SetRedisAll(ctx context.Context, task model.ExportTensorTask, all int64) error
	DeleteRedisData(ctx context.Context, task model.ExportTensorTask) error
}

type ExcelMetaData struct {
	SheetName string
	FileName  string
	Header    []string
}

type ExcelMetaDataOption func(data *ExcelMetaData)

// key：excel sheet name
// value：`chan []string`：表示一个sheet的数据流(一个镜像或一个漏洞的数据)
// 为啥使用：[] chan []string ，因为要导出多个镜像
type ExcelData map[string][]chan []string

type ExcelDataWithMeta struct {
	ExcelData     ExcelData
	Filename      string
	ExcelMetaData []ExcelMetaData
}

type ImageInterface interface {
	GetImageCorrelateData(ctx context.Context, param model.GetImageAssociateDataParam) (*model.ImageWithCorrelateData, error)
	ListImageWithScanInfo(ctx context.Context, param model.ImageListParam, filter *model.Filter) ([]*model.ImageBaseResponse, int64, error)
}

func WriteToExcel(filenamePrefix string, sheets []ExcelMetaData, data ExcelData) (*excelize.File, error) {
	if data == nil {
		return nil, fmt.Errorf("WriteToExcel  data is nil")
	}
	if filenamePrefix == "" {
		return nil, fmt.Errorf("filename is nil")
	}
	start := time.Now().UnixMilli()
	file := excelize.NewFile()
	file.Path = filenamePrefix + ".xlsx"
	logging.Get().Info().Str("excelPath", file.Path).Msg("WriteToExcel")

	styleID, err := file.NewStyle(&excelize.Style{Font: &excelize.Font{Color: "#777777"}})
	if err != nil {
		styleID = 0
	}

	for i := range sheets {
		// 写入数据，用流式方式
		idx := file.NewSheet(sheets[i].SheetName)
		file.SetActiveSheet(idx)

		// 先写头数据
		streamWriter, err := file.NewStreamWriter(sheets[i].SheetName)
		if err != nil {
			return nil, err
		}

		data2 := make([]interface{}, len(sheets[i].Header))
		for j := range sheets[i].Header {
			data2[j] = sheets[i].Header[j]
		}

		cell, err := excelize.CoordinatesToCellName(1, 1)
		if err != nil {
			return nil, err
		}
		if err := streamWriter.SetRow(cell, data2, excelize.RowOpts{StyleID: styleID}); err != nil {
			return nil, err
		}
		// 再写数据
		col := 2

		sheetDataSlice := data[sheets[i].SheetName]

		for j := range sheetDataSlice {
			sheetDataChan := sheetDataSlice[j]
			for sheetData := range sheetDataChan {
				data3 := make([]interface{}, len(sheetData))
				for k := range sheetData {
					data3[k] = sheetData[k]
				}

				cell, err = excelize.CoordinatesToCellName(1, col)
				if err != nil {
					return nil, err
				}
				if err := streamWriter.SetRow(cell, data3); err != nil {
					return nil, err
				}
				col++
			}
		}
		// 刷新数据
		if err := streamWriter.Flush(); err != nil {
			return nil, err
		}
	}
	file.DeleteSheet("Sheet1")
	file.SetActiveSheet(0)

	logging.Get().Info().Int64("cost", time.Now().UnixMilli()-start).Msg("WriteToExcel")

	return file, nil
}

// 把多个excel打包成一个zip文件返回,
func ZipExcelFile(files chan *excelize.File) (io.Reader, error) {
	b := new(bytes.Buffer)

	zw := zip.NewWriter(b)

	for {
		file, ok := <-files
		if !ok {
			break
		}
		logging.Get().Info().Str("filePath", file.Path).Msg("ZipExcelFile get file")
		hdr := zip.FileHeader{Name: file.Path}
		w, err := zw.CreateHeader(&hdr)
		if err != nil {
			return nil, err
		}

		buff, err := file.WriteToBuffer()
		if err != nil {
			return nil, err
		}
		_, err = io.Copy(w, buff)
		if err != nil {
			return nil, err
		}
		if err := file.Close(); err != nil {
			return nil, err
		}
	}

	if err := zw.Flush(); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}

	logging.Get().Info().Msg("ZipExcelFile get all file, zip complete")

	return b, nil
}

func checkFileIsExist(filename string) bool {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return false
	}
	return true
}

func DeleteFile(filename string) error {
	if checkFileIsExist(filename) {
		return os.Remove(filename)
	}
	return nil
}

func SaveFile(reader io.Reader, filenamePrefix string) error {

	filename := filenamePrefix + ".zip"

	if checkFileIsExist(filename) {
		// 如果文件存在就先删除该文件
		if err := DeleteFile(filename); err != nil {
			return err
		}
	}

	f, err := os.Create(filename) // 创建文件
	if err != nil {
		return err
	}
	defer func() {
		if err := f.Close(); err != nil {
			logging.Get().Err(err).Msg("SaveFile.Close")
		}
	}()

	w := bufio.NewWriter(f)

	_, err = w.ReadFrom(reader)
	if err != nil {
		return err
	}
	if err := w.Flush(); err != nil {
		return err
	}

	return nil
}

type UpdateTaskSrv struct {
	ExportTaskDal store.ExportTaskDal
	RedisCli      *redis.Client
}

func NewUpdateTaskSrv(exportTaskDal store.ExportTaskDal, redisCli *redis.Client) *UpdateTaskSrv {
	return &UpdateTaskSrv{ExportTaskDal: exportTaskDal, RedisCli: redisCli}
}

func (s *UpdateTaskSrv) Success(ctx context.Context, id int64, filePath string) error {
	updater := map[string]interface{}{"finish_at": time.Now().Unix(), "file_path": filePath}
	where := fmt.Sprintf("id = %d", id)
	if err := s.ExportTaskDal.UpdateExportTensorTask(ctx, where, updater, nil); err != nil {
		logging.Get().Err(err).Int64("taskID", id).Msg("Success")
		return err
	}
	return nil
}

func (s *UpdateTaskSrv) IncrRedisFinished(ctx context.Context, task model.ExportTensorTask) error {

	err := s.RedisCli.Incr(ctx, task.GenRedisFinishedKey()).Err()
	if err != nil {
		logging.Get().Err(err).Int64("taskID", task.ID).Msg("UpdateTaskSrv setAll")
	}
	return err
}

func (s *UpdateTaskSrv) SetRedisAll(ctx context.Context, task model.ExportTensorTask, all int64) error {
	err := s.RedisCli.Set(ctx, task.GenRedisAllKey(), all, 0).Err()
	if err != nil {
		logging.Get().Err(err).Int64("taskID", task.ID).Msg("UpdateTaskSrv setAll")
	}
	return err
}

func (s *UpdateTaskSrv) DeleteRedisData(ctx context.Context, task model.ExportTensorTask) error {
	var err error
	err = s.RedisCli.Del(ctx, task.GenRedisAllKey()).Err()
	err = s.RedisCli.Del(ctx, task.GenRedisFinishedKey()).Err()

	if err != nil && err != redis.Nil {
		logging.Get().Err(err).Int64("taskID", task.ID).Msg("UpdateTaskSrv deleteRedisData")
	}
	return err
}

func (s *UpdateTaskSrv) Failure(ctx context.Context, id int64, msg string) error {
	updater := map[string]interface{}{"err_msg": msg, "finish_at": time.Now().Unix()}
	where := fmt.Sprintf("id = %d", id)
	if err := s.ExportTaskDal.UpdateExportTensorTask(ctx, where, updater, nil); err != nil {
		logging.Get().Err(err).Int64("taskID", id).Msg("Failure")
		return err
	}
	return nil
}

func (s *UpdateTaskSrv) Start(ctx context.Context, id int64) error {
	updater := map[string]interface{}{"start_at": time.Now().Unix()}
	where := fmt.Sprintf("id = %d", id)
	if err := s.ExportTaskDal.UpdateExportTensorTask(ctx, where, updater, nil); err != nil {
		logging.Get().Err(err).Int64("taskID", id).Msg("Start")
		return err
	}
	return nil
}
