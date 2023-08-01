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

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/scan-report/export/common"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/scan-report/types"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type VulnExport struct {
	ExportTaskDal imagesecStore.ExportTaskDal
	FileDir       string // 文件存储的决对路径
	ImageSrv      types.ImageSrvInterface
	scanResultDal imagesecStore.ScanResultDal
	UpdateTask    types.UpdateExportTask
}

func NewVulnExport(
	exportTaskDal imagesecStore.ExportTaskDal,
	fileDir string, // 文件存储的决对路径
	scanResultDal imagesecStore.ScanResultDal,
	imageSrv types.ImageSrvInterface,
	updateTask types.UpdateExportTask,
) *VulnExport {
	return &VulnExport{
		ExportTaskDal: exportTaskDal,
		FileDir:       fileDir,
		scanResultDal: scanResultDal,
		ImageSrv:      imageSrv,
		UpdateTask:    updateTask,
	}
}

func (s *VulnExport) GetTensorTask(ctx context.Context, executeType string, n int64) ([]model.ExportTensorTask, error) {
	tasks, _, err := s.ExportTaskDal.SearchExportTask(ctx, imagesec.SearchExportTaskParam{
		ExecuteType: []string{executeType},
		TaskType:    model.ExportExcel,
		Finished:    consts.FalseString,
		Failure:     consts.FalseString,
		Filter:      &model.Filter{Limit: n},
	})
	if err != nil {
		logging.Get().Err(err).Str("ExecuteType", executeType).Msg("GetTensorTask")
		return nil, err
	}
	return tasks, nil
}

func (s *VulnExport) Run(ctx context.Context) {
	tasks, err := s.GetTensorTask(ctx, consts.ExportVuln, consts.DefaultExportBathSize)
	if err != nil {
		logging.Get().Err(err).Msg("SearchExportTask")
		return
	}

	for i := range tasks {
		// 支持横向扩展
		// created, err := s.ExportTaskDal.CreateExportIdempotent(ctx, tasks[i].ID)
		// if err != nil {
		// 	logging.Get().Err(err).Str("TaskType", model.ExportHtml).Msg("VulnExportExcel CreateExportIdempotent")
		// 	return
		// }
		// if !created {
		// 	continue
		// }

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
	UniqueVuln string `json:"uniqueID"`
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

	vulns, _, err := s.scanResultDal.SearchVuln(ctx, imagesec.SearchVulnDalParam{VulnUniqueID: uv})
	if err != nil {
		logging.Get().Err(err).Int64("taskID", task.ID).Str("UniqueVuln", searchParam.UniqueVuln).Msg("SearchVuln")
		return err
	}
	if len(vulns) == 0 {
		logging.Get().Err(err).Int64("taskID", task.ID).Str("UniqueVuln", searchParam.UniqueVuln).Msg("not find vuln")
		return fmt.Errorf("not fond the vulns:%s", searchParam.UniqueVuln)
	}
	// 查对应的镜像
	vulnImage, _, err := s.ImageSrv.ListImageWithScanInfo(ctx, imagesec.ImageSearchApiParam{VulnUniqueID: uv})
	if err != nil {
		logging.Get().Err(err).Int64("taskID", task.ID).Str("UniqueVuln", searchParam.UniqueVuln).Msg("SearchVulnImage")
		return err
	}

	resources := make([]*imagesec.ImageWithCorrelateData2, 0)
	if len(vulnImage) > 0 {
		for i := range vulnImage {
			data, err := s.ImageSrv.GetImageCorrelateData(ctx, imagesec.GetImageAssociateDataParam{ImageId: vulnImage[i].ID, ContainerEnable: true})
			if err != nil {
				logging.Get().Err(err).Int64("taskID", task.ID).Int64("imageID", vulnImage[i].ID).Msg("GetImageCorrelateData")
				continue
			}
			resources = append(resources, data)
		}
	}

	fileName := fmt.Sprintf("%s_%d", vulns[0].Name, time.Now().Unix())
	vulnData := vulns[0].GenVulnView()
	vulnData.AdaptI18(context.WithValue(ctx, model.AcceptLanguage, task.Lang))

	excelChan := s.Export(ctx, fileName, vulnData, resources, task)

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

func (s *VulnExport) Export(ctx context.Context, filename string, vuln *imagesec.VulnView,
	imageContainers []*imagesec.ImageWithCorrelateData2, task model.ExportTensorTask) chan *excelize.File {
	out := make(chan *excelize.File, 1)

	go func() {

		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("VulnExportExcel")
			}
		}()

		defer close(out)

		logging.Get().Info().Str("vuln", vuln.Name).Msg("Export Vuln start")
		excelData := make(map[types.SheetName][]chan []string)
		// 加入漏洞数据
		vulnSheetName := common.GenImageVulnInfoMeta(task.Lang).SheetName
		resourceSheetName := common.GenImageResourcesInfoMeta(task.Lang).SheetName
		if excelData[vulnSheetName] == nil {
			excelData[vulnSheetName] = make([]chan []string, 0)
		}

		vuln.AdaptI18(context.WithValue(ctx, model.AcceptLanguage, task.Lang))

		vulnData := common.GenVulnInfoChan(imagesec.ImageBaseResponse{}, []*imagesec.VulnView{vuln}, task.Lang)
		vulnChan := s.ConvertVulnData(vulnData)
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
				s.ConvertResourceData(common.GenImageResourceChan(ic.ToImageBaseResponse(), ic.Container)))
		}

		sheets := common.GetVulnSheetInfo(task.Lang)
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
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("VulnExportExcel")
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
				logging.Get().Error().Str("stack", string(debug.Stack())).Msg("VulnExportExcel")
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

func (s *VulnExport) ConvertData(res map[types.SheetName]chan []string, task model.ExportTensorTask) map[types.SheetName]chan []string {

	ans := make(map[types.SheetName]chan []string)

	for key, value := range res {

		if key == common.GenImageVulnInfoMeta(task.Lang).SheetName {
			out := make(chan []string, 1)
			go func(value chan []string) {

				defer func() {
					if r := recover(); r != nil {
						logging.Get().Error().Str("stack", string(debug.Stack())).Msg("VulnExportExcel")
					}
				}()

				defer close(out)

				for data := range value {
					data = data[2:]
					out <- data
				}
			}(value)
			ans[key] = out
		} else if key == common.GenImageResourcesInfoMeta(task.Lang).SheetName {
			out := make(chan []string, 1)
			go func(value chan []string) {
				defer func() {
					if r := recover(); r != nil {
						logging.Get().Error().Str("stack", string(debug.Stack())).Msg("VulnExportExcel")
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
