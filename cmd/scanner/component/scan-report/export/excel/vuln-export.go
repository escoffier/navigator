package excel

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/xuri/excelize/v2"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/export"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type VulnExport struct {
	ExportTaskDal store.ExportTaskDal
	ExportingMap  *sync.Map // 正在执行的任务
	FileDir       string    // 文件存储的决对路径
	VulnDal       store.VulnDalInterface
	ImageDal      store.ScannerDalInterface
	ResourceDal   store.ResourceDal
	UpdateTask    export.UpdateTask
}

func NewVulnExport(
	exportTaskDal store.ExportTaskDal,
	fileDir string, // 文件存储的决对路径
	vulnDal store.VulnDalInterface,
	imageDal store.ScannerDalInterface,
	resourceDal store.ResourceDal,
	updateTask export.UpdateTask,
) *VulnExport {
	return &VulnExport{
		ExportTaskDal: exportTaskDal,
		ExportingMap:  &sync.Map{},
		FileDir:       fileDir,
		VulnDal:       vulnDal,
		ImageDal:      imageDal,
		ResourceDal:   resourceDal,
		UpdateTask:    updateTask,
	}
}

func (s *VulnExport) GetTensorTask(ctx context.Context, executeType string, n int64) ([]model.ExportTensorTask, error) {
	tasks, _, err := s.ExportTaskDal.SearchExportTensorTask(ctx, store.SearchExportTensorTask{
		ExecuteType: []string{executeType},
		TaskType:    model.ExportExcel,
		Finished:    consts.FalseString,
		Failure:     consts.FalseString,
	}, &model.Filter{Limit: n})
	if err != nil {
		logging.GetLogger().Err(err).Str("ExecuteType", executeType).Msg("GetTensorTask")
		return nil, err
	}
	return tasks, nil
}

func (s *VulnExport) Run(ctx context.Context) {
	tasks, err := s.GetTensorTask(ctx, consts.ExportVuln, consts.DefaultExportBathSize)
	if err != nil {
		logging.GetLogger().Err(err).Msg("SearchExportTensorTask")
		return
	}

	for i := range tasks {
		if err := s.UpdateTask.Start(ctx, tasks[i].ID); err != nil {
			logging.GetLogger().Err(err).Int64("taskID", tasks[i].ID).Msg("Run.Start")
			continue
		}

		if err := s.worker(ctx, tasks[i]); err != nil {
			logging.GetLogger().Err(err).Msg("worker")
		}
	}
}

type VulnExportParma struct {
	UniqueVuln string `json:"uniqueVuln"`
}

// 取一个任务来执行
func (s *VulnExport) worker(ctx context.Context, task model.ExportTensorTask) error {
	// 检查同样的任务是否已经做过
	tensorTask, _, err := s.ExportTaskDal.SearchExportTensorTask(ctx,
		store.SearchExportTensorTask{ExecuteType: []string{consts.ExportVuln},
			Parameter: task.Parameter, NotIds: []int64{task.ID}}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Int64("taskID", task.ID).Msg("SearchExportTensorTask")
		return err
	}
	if len(tensorTask) > 0 && tensorTask[0].FinishAt > 0 {
		// 如果上一次执行成功了,成功之后更新任务
		if err := s.UpdateTask.Success(ctx, task.ID, tensorTask[0].FilePath); err != nil {
			logging.GetLogger().Err(err).Int64("taskID", task.ID).Msg("Success export task success update task")
		}
		return err
	}

	if ex, ok := s.ExportingMap.Load(task.ID); ok {
		if ex1, ok := ex.(bool); ok && ex1 == consts.TaskExporting {
			logging.GetLogger().Info().Int64("taskID", task.ID).Msg("task is running")
			return nil
		}
	}

	s.ExportingMap.Store(task.ID, consts.TaskExporting)

	searchParam := VulnExportParma{}

	if err := json.Unmarshal([]byte(task.Parameter), &searchParam); err != nil {
		return err
	}
	uv, err := strconv.ParseUint(searchParam.UniqueVuln, 10, 64)
	if err != nil {
		logging.GetLogger().Err(err).Int64("taskID", task.ID).Msg("Unmarshal.VulnExportParma")
		return fmt.Errorf("uniqueVuln incorrect")
	}

	vulns, _, err := s.VulnDal.SearchVuln(ctx, store.SearchVulnParam{UniqueVulns: []uint64{uv}}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Int64("taskID", task.ID).Str("UniqueVuln", searchParam.UniqueVuln).Msg("SearchVuln")
		return err
	}
	if len(vulns) == 0 {
		logging.GetLogger().Err(err).Int64("taskID", task.ID).Str("UniqueVuln", searchParam.UniqueVuln).Msg("not find vuln")
		return fmt.Errorf("not fond the vulns:%s", searchParam.UniqueVuln)
	}
	// 查对应的镜像
	vulnImage, _, err := s.VulnDal.SearchVulnImage(ctx, store.SearchVulnImageParam{UniqueVulns: []uint64{vulns[0].UniqueVuln}}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Int64("taskID", task.ID).Str("UniqueVuln", searchParam.UniqueVuln).Msg("SearchVulnImage")
		return err
	}
	resources := make([]ResourceWithImage, 0)
	if len(vulnImage) > 0 {
		imageIds := make([]int64, 0)
		for i := range vulnImage {
			imageIds = append(imageIds, vulnImage[i].ImageId)
		}
		images, _, err := s.ImageDal.SearchImage(ctx, store.SearchImageParam{InIds: imageIds}, nil)
		if err != nil {
			logging.GetLogger().Err(err).Int64("taskID", task.ID).Str("UniqueVuln", searchParam.UniqueVuln).Msg("SearchImage")
			return err
		}
		uuids := make([]uint32, 0)
		imageMap := make(map[uint32]model.ImageList)
		for i := range images {
			uuids = append(uuids, images[i].ImageUUID)
			imageMap[images[i].ImageUUID] = images[i]
		}
		if len(uuids) > 0 {
			res, err := s.ResourceDal.SearchResources(ctx, uuids)
			if err != nil {
				logging.GetLogger().Err(err).Int64("taskID", task.ID).Str("UniqueVuln", searchParam.UniqueVuln).Msg("SearchResources")
				return err
			}
			resources2 := make([]ResourceWithImage, 0)
			for i := range res {
				resources2 = append(resources2, ResourceWithImage{
					Image:    imageMap[res[i].ImageUUID],
					Resource: []store.TensorResources{res[i]},
				})
			}
			resources = resources2
		}
	}

	fileName := fmt.Sprintf("%s_%d", vulns[0].Name, time.Now().Unix())

	excelChan := s.Export(ctx, fileName, *(vulns[0]), resources)

	if err := s.ZipAndSave(ctx, fileName, excelChan); err != nil {
		logging.GetLogger().Err(err).Int64("taskID", task.ID).Msg("ZipAndSave")
		s.ExportingMap.Delete(task.ID)

		if err := s.UpdateTask.Failure(ctx, task.ID, err.Error()); err != nil {
			logging.GetLogger().Err(err).Int64("taskID", task.ID).Msg("Failure export task failure update task")
		}
		return err
	}
	s.ExportingMap.Delete(task.ID)
	// 成功之后更新任务
	if err := s.UpdateTask.Success(ctx, task.ID, fmt.Sprintf("%s/%s.zip", s.FileDir, fileName)); err != nil {
		logging.GetLogger().Err(err).Int64("taskID", task.ID).Msg("Success export task success update task")
	}
	return nil
}

type ResourceWithImage struct {
	Image    model.ImageList
	Resource []store.TensorResources
}

// 压缩并写入文件，filename 路径名
func (s *VulnExport) ZipAndSave(ctx context.Context, filename string, files chan *excelize.File) error {
	file, err := ZipExcelFile(files)
	if err != nil {
		logging.GetLogger().Err(err).Str("filename", filename).Msg("ZipAndSave.ZipExcelFile")
		return err
	}
	logging.GetLogger().Info().Str("filename", filename).Msg("ZipAndSave.ZipExcelFile")

	if err := SaveFile(file, s.FileDir+"/"+filename); err != nil {
		logging.GetLogger().Err(err).Str("filename", filename).Msg("ZipAndSave.SaveFile")
		return err
	}
	logging.GetLogger().Info().Str("filename", filename).Msg("ZipAndSave.SaveFile")
	return nil
}

func (s *VulnExport) Export(ctx context.Context, filename string, vuln model.Vuln, resources []ResourceWithImage) chan *excelize.File {
	out := make(chan *excelize.File)

	go func(filename string, vuln model.Vuln, resources []ResourceWithImage) {
		defer close(out)
		logging.GetLogger().Info().Str("vuln", vuln.Name).Msg("Export Vuln start")

		excelData := make(map[string][]chan []string)
		// 加入漏洞数据
		vulnSheetName := GenImageVulnInfoMeta().SheetName
		resourceSheetName := GenImageResourcesInfoMeta().SheetName
		if excelData[vulnSheetName] == nil {
			excelData[vulnSheetName] = make([]chan []string, 0)
		}

		excelData[vulnSheetName] = append(excelData[vulnSheetName], s.ConvertVulnData(
			GenVulnInfoChan(model.ImageList{ImageScanVuln: model.ImageScanSummaryResult{Vulns: []*model.Vuln{&vuln}}}, nil)))

		// 加入关联资源的数据
		if excelData[resourceSheetName] == nil {
			excelData[resourceSheetName] = make([]chan []string, 0)
		}
		for i := range resources {
			excelData[resourceSheetName] = append(excelData[resourceSheetName], s.ConvertResourceData(
				GenImageResourceChan(resources[i].Image, resources[i].Resource)))
		}

		logging.GetLogger().Info().Str("vuln", vuln.Name).Msg("ExportVuln.GetExcelData")

		sheets := GetVulnSheetInfo()
		excelFile, err := WriteToExcel(filename, sheets, excelData)
		if err != nil {
			logging.GetLogger().Err(err).Msg("Export.WriteToExcel")
			return
		}

		out <- excelFile
		logging.GetLogger().Info().Str("vuln", vuln.Name).Msg("Export Vuln completed")
	}(filename, vuln, resources)

	return out
}

func (s *VulnExport) ConvertVulnData(res chan []string) chan []string {
	out := make(chan []string)
	go func(value chan []string) {
		defer close(out)
		for data := range value {
			data = data[2:]
			out <- data
		}
	}(res)
	return out
}

func (s *VulnExport) ConvertResourceData(res chan []string) chan []string {
	out := make(chan []string)
	go func(value chan []string) {
		defer close(out)
		for data := range value {
			data = append(data[:1], data[2:]...)
			out <- data
		}
	}(res)
	return out
}

func (s *VulnExport) ConvertData(res map[string]chan []string) map[string]chan []string {

	ans := make(map[string]chan []string)

	for key, value := range res {

		if key == GenImageVulnInfoMeta().SheetName {
			out := make(chan []string)
			go func(value chan []string) {
				defer close(out)
				for data := range value {
					data = data[2:]
					out <- data
				}
			}(value)
			ans[key] = out
		} else if key == GenImageResourcesInfoMeta().SheetName {
			out := make(chan []string)
			go func(value chan []string) {
				defer close(out)
				for data := range value {
					data = append(data[:1], data[2:]...)
					out <- data
				}
			}(value)
			ans[key] = out
		}

	}
	return ans
}
