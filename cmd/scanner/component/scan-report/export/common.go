package export

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/xuri/excelize/v2"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type ExcelMetaData struct {
	SheetName string
	FileName  string
	Header    []string
}

type ExcelMetaDataOption func(data *ExcelMetaData)

func ToString(value interface{}) string {
	return fmt.Sprintf("%v", value)
}

func WriteToExcel(filenamePrefix string, sheets []ExcelMetaData, data map[string][]chan []string) (*excelize.File, error) {
	if data == nil {
		return nil, fmt.Errorf("WriteToExcel  data is nil")
	}
	if filenamePrefix == "" {
		return nil, fmt.Errorf("filename is nil")
	}
	start := time.Now().UnixMilli()
	file := excelize.NewFile()
	file.Path = filenamePrefix + ".xlsx"
	logging.GetLogger().Info().Str("excelPath", file.Path).Msg("WriteToExcel")
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
		if err := streamWriter.SetRow(cell, data2); err != nil {
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

				cell, err := excelize.CoordinatesToCellName(1, col)
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

	logging.GetLogger().Info().Int64("cost", time.Now().UnixMilli()-start).Msg("WriteToExcel")

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
		logging.GetLogger().Info().Str("filePath", file.Path).Msg("ZipExcelFile get file")
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

	logging.GetLogger().Info().Msg("ZipExcelFile get all file, zip complete")

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
			logging.GetLogger().Err(err).Msg("SaveFile.Close")
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

// 注意 下标从1开始
func GenExcelTitle(columnNumber int) string {
	ans := ""
	for columnNumber > 26 {
		num := columnNumber % 26
		if num == 0 {
			ans = "Z" + ans
			columnNumber = (columnNumber / 26) - 1
		} else {
			ans = string(byte(64+num)) + ans
			columnNumber = columnNumber / 26
		}
	}
	ans = string(byte(columnNumber+64)) + ans
	return ans
}

type UpdateExportTask interface {
	Success(ctx context.Context, id int64) error
	Failure(ctx context.Context, id int64, msg string) error
}

type DataExportInterface interface {
	GetTensorTask(ctx context.Context, executeType string, n int64) ([]model.ExportTensorTask, error)
	ZipAndSave(ctx context.Context, files []*excelize.File, filename string) error
}

type DataExportTask struct {
	exportTaskDal store.ExportTaskDal
}

func (s *DataExportTask) Success(ctx context.Context, id int64) error {

	updater := map[string]interface{}{"finish_at": time.Now().Unix()}
	where := fmt.Sprintf("id = %d", id)
	if err := s.exportTaskDal.UpdateExportTensorTask(ctx, where, updater, nil); err != nil {
		logging.GetLogger().Err(err).Int64("taskId", id).Msg("Success")
		return err
	}
	return nil

}

func (s *DataExportTask) Failure(ctx context.Context, id int64, msg string) error {
	updater := map[string]interface{}{"err_msg": msg}
	where := fmt.Sprintf("id = %d", id)
	if err := s.exportTaskDal.UpdateExportTensorTask(ctx, where, updater, nil); err != nil {
		logging.GetLogger().Err(err).Int64("taskId", id).Msg("Failure")
		return err
	}
	return nil

}

func MkdirIfNotExist(path string) error {
	stat, err := os.Stat(path)
	if err == nil {
		if stat.IsDir() {
			return nil
		} else {
			// 先删除这个文件再创建
			logging.GetLogger().Info().Str("filename", path).Msg("file exist remove it")
			if err := os.Remove(path); err != nil {
				return err
			}
			return os.Mkdir(path, os.ModePerm)
		}
	}
	if os.IsNotExist(err) {
		return os.Mkdir(path, os.ModePerm)
	}
	return err
}
