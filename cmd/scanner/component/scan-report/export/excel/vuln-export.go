package excel

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/xuri/excelize/v2"
	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scan-report/common"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type VulnExport struct {
	ExportTaskDal store.ExportTaskDal
	FileDir       string // 文件存储的决对路径
	ImageSrv      common.ImageInterface
	VulnDal       store.VulnDalInterface
	UpdateTask    common.UpdateExportTask
}

func NewVulnExport(
	exportTaskDal store.ExportTaskDal,
	fileDir string, // 文件存储的决对路径
	vulnDal store.VulnDalInterface,
	updateTask common.UpdateExportTask,
) *VulnExport {
	return &VulnExport{
		ExportTaskDal: exportTaskDal,
		FileDir:       fileDir,
		VulnDal:       vulnDal,
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
		logging.Get().Err(err).Str("ExecuteType", executeType).Msg("GetTensorTask")
		return nil, err
	}
	return tasks, nil
}

func (s *VulnExport) Run(ctx context.Context) {
	tasks, err := s.GetTensorTask(ctx, consts.ExportVuln, consts.DefaultExportBathSize)
	if err != nil {
		logging.Get().Err(err).Msg("SearchExportTensorTask")
		return
	}

	for i := range tasks {
		// 支持横向扩展
		created, err := s.ExportTaskDal.CreateExportIdempotent(ctx, tasks[i].ID)
		if err != nil {
			logging.Get().Err(err).Str("TaskType", model.ExportHtml).Msg("VulnExport CreateExportIdempotent")
			return
		}
		if !created {
			continue
		}

		if err := s.UpdateTask.Start(ctx, tasks[i].ID); err != nil {
			logging.Get().Err(err).Int64("taskID", tasks[i].ID).Msg("Run.Start")
			continue
		}

		if err := s.worker(ctx, tasks[i]); err != nil {
			logging.Get().Err(err).Msg("worker")
			if err := s.UpdateTask.Failure(ctx, tasks[i].ID, err.Error()); err != nil {
				logging.Get().Err(err).Int64("taskID", tasks[i].ID).Msg("Failure export task failure update task")
			}
		}
	}
}

type VulnExportParma struct {
	UniqueVuln string `json:"uniqueVuln"`
}

// 取一个任务来执行
func (s *VulnExport) worker(ctx context.Context, task model.ExportTensorTask) error {
	searchParam := VulnExportParma{}
	if err := json.Unmarshal([]byte(task.Parameter), &searchParam); err != nil {
		return err
	}
	uv, err := strconv.ParseUint(searchParam.UniqueVuln, 10, 64)
	if err != nil {
		logging.Get().Err(err).Int64("taskID", task.ID).Msg("Unmarshal.VulnExportParma")
		return fmt.Errorf("uniqueVuln incorrect")
	}

	vulns, _, err := s.VulnDal.SearchVuln(ctx, store.SearchVulnParam{UniqueVulns: []uint64{uv}}, nil)
	if err != nil {
		logging.Get().Err(err).Int64("taskID", task.ID).Str("UniqueVuln", searchParam.UniqueVuln).Msg("SearchVuln")
		return err
	}
	if len(vulns) == 0 {
		logging.Get().Err(err).Int64("taskID", task.ID).Str("UniqueVuln", searchParam.UniqueVuln).Msg("not find vuln")
		return fmt.Errorf("not fond the vulns:%s", searchParam.UniqueVuln)
	}
	// 查对应的镜像
	vulnImage, _, err := s.VulnDal.SearchVulnImage(ctx, store.SearchVulnImageParam{UniqueVulns: []uint64{vulns[0].UniqueVuln}}, nil)
	if err != nil {
		logging.Get().Err(err).Int64("taskID", task.ID).Str("UniqueVuln", searchParam.UniqueVuln).Msg("SearchVulnImage")
		return err
	}

	resources := make([]*model.ImageWithCorrelateData, 0)
	if len(vulnImage) > 0 {
		for i := range vulnImage {
			data, err := s.ImageSrv.GetImageCorrelateData(ctx, model.GetImageAssociateDataParam{ImageId: vulnImage[i].ImageId, ContainerEnable: true})
			if err != nil {
				logging.Get().Err(err).Int64("taskID", task.ID).Int64("imageID", vulnImage[i].ImageId).Msg("GetImageCorrelateData")
				continue
			}
			resources = append(resources, data)
		}
	}

	fileName := fmt.Sprintf("%s_%d", vulns[0].Name, time.Now().Unix())

	excelChan := s.Export(ctx, fileName, vulns[0], resources)

	if err := s.ZipAndSave(ctx, fileName, excelChan); err != nil {
		logging.Get().Err(err).Int64("taskID", task.ID).Msg("ZipAndSave")
		return err
	}
	// 成功之后更新任务
	if err := s.UpdateTask.Success(ctx, task.ID, fmt.Sprintf("%s/%s.zip", s.FileDir, fileName)); err != nil {
		logging.Get().Err(err).Int64("taskID", task.ID).Msg("Success export task success update task")
	}
	return nil
}

// 压缩并写入文件，filename 路径名
func (s *VulnExport) ZipAndSave(ctx context.Context, filename string, files chan *excelize.File) error {
	file, err := common.ZipExcelFile(files)
	if err != nil {
		logging.Get().Err(err).Str("filename", filename).Msg("ZipAndSave.ZipExcelFile")
		return err
	}
	logging.Get().Info().Str("filename", filename).Msg("ZipAndSave.ZipExcelFile")

	if err := common.SaveFile(file, s.FileDir+"/"+filename); err != nil {
		logging.Get().Err(err).Str("filename", filename).Msg("ZipAndSave.SaveFile")
		return err
	}
	logging.Get().Info().Str("filename", filename).Msg("ZipAndSave.SaveFile")
	return nil
}

func (s *VulnExport) Export(ctx context.Context, filename string, vuln *model.Vuln, imageContainers []*model.ImageWithCorrelateData) chan *excelize.File {
	out := make(chan *excelize.File, 1)

	go func() {

		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("VulnExport")
			}
		}()

		defer close(out)

		logging.Get().Info().Str("vuln", vuln.Name).Msg("Export Vuln start")
		excelData := make(map[string][]chan []string)
		// 加入漏洞数据
		vulnSheetName := GenImageVulnInfoMeta().SheetName
		resourceSheetName := GenImageResourcesInfoMeta().SheetName
		if excelData[vulnSheetName] == nil {
			excelData[vulnSheetName] = make([]chan []string, 0)
		}

		vulnChan := s.ConvertVulnData(GenVulnInfoChan(model.ImageBaseResponse{}, []*model.Vuln{vuln}, nil))
		excelData[vulnSheetName] = append(excelData[vulnSheetName], vulnChan)

		// 加入关联资源的数据
		if excelData[resourceSheetName] == nil {
			excelData[resourceSheetName] = make([]chan []string, 0)
		}
		for i := range imageContainers {
			ic := imageContainers[i]
			if len(ic.Container) == 0 {
				continue
			}
			excelData[resourceSheetName] = append(excelData[resourceSheetName],
				s.ConvertResourceData(GenImageResourceChan(ic.ToImageBaseResponse(), ic.Container)))
		}

		sheets := GetVulnSheetInfo()
		excelFile, err := common.WriteToExcel(filename, sheets, excelData)
		if err != nil {
			logging.Get().Err(err).Msg("Export.WriteToExcel")
			return
		}

		out <- excelFile
		logging.Get().Info().Str("vuln", vuln.Name).Msg("Export Vuln completed")
	}()

	return out
}

func (s *VulnExport) ConvertVulnData(res chan []string) chan []string {
	out := make(chan []string, 1)
	go func(value chan []string) {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("VulnExport")
			}
		}()

		defer close(out)

		for data := range value {
			data = data[2:]
			out <- data
		}
	}(res)
	return out
}

// 漏洞导出时
func (s *VulnExport) ConvertResourceData(res chan []string) chan []string {
	out := make(chan []string, 1)
	go func(value chan []string) {

		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("VulnExport")
			}
		}()
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
			out := make(chan []string, 1)
			go func(value chan []string) {

				defer func() {
					if r := recover(); r != nil {
						logging.Get().Error().Str("stack", string(debug.Stack())).Msg("VulnExport")
					}
				}()

				defer close(out)

				for data := range value {
					data = data[2:]
					out <- data
				}
			}(value)
			ans[key] = out
		} else if key == GenImageResourcesInfoMeta().SheetName {
			out := make(chan []string, 1)
			go func(value chan []string) {
				defer func() {
					if r := recover(); r != nil {
						logging.Get().Error().Str("stack", string(debug.Stack())).Msg("VulnExport")
					}
				}()

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
