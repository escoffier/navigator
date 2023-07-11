package dbManage

import (
	"context"
	"fmt"
	"mime/multipart"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/task"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagemeta"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan"
	imagesecSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagesec"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"

	"github.com/gin-gonic/gin"
	"gitlab.com/security-rd/go-pkg/logging"

	vulnupdata "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/vuln-updata"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/global"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/stream"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	scannermodel "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-model"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
)

type DBManage struct {
	dal   store.VersionDal
	upSrv *vulnupdata.UpdateVersionSrv
}

func NewDBManage(dal store.VersionDal) DBManage {
	return DBManage{dal: dal, upSrv: vulnupdata.GetUpdateVersionSrv()}
}

func (v *DBManage) GetParseInt(ctx *gin.Context, s string) int64 {
	str := ctx.Query(s)
	if str == "" {
		return 0
	}
	num, err := strconv.ParseInt(str, 10, 64)
	if err != nil {
		logging.Get().Err(err).Msgf("Parse %v error str :%v", s, str)
		return 0
	}
	return num
}

func (v *DBManage) ListVersions(ctx *gin.Context) {
	clusterKey := ctx.Query("cluster_key")
	limit := v.GetParseInt(ctx, "limit")
	offset := v.GetParseInt(ctx, "offset")
	res, _, err := v.dal.SearchVersion(ctx, store.SearchVersionParam{ClusterKey: clusterKey}, model.Filter{Limit: limit, Offset: offset})
	if err != nil {
		logging.Get().Err(err).Msgf("search version error")
		response.JSONError(ctx, fmt.Errorf("search %v error", clusterKey))
		return
	}
	response.JSONOK(ctx, response.WithItems(res))
}

func (v *DBManage) GetSubVersion(ctx *gin.Context, objType string) ([]scannermodel.ScanDBVersion, error) {
	res, _, err := v.dal.SearchVersion(ctx, store.SearchVersionParam{}, model.Filter{})
	if err != nil {
		logging.Get().Err(err).Msg("get sub version error")
		return nil, err
	}
	mainMaliciousVer := scannermodel.MaliciousDBVersion{}
	mainVulnVer := scannermodel.VulnDBVersion{}
	for k := range res {
		if res[k].KeyPath == scannermodel.MainScannerObject {
			mainVulnVer = res[k].VulnDBVersion
			mainMaliciousVer.Avira = res[k].AviraDBVersion
			mainMaliciousVer.Clamav = res[k].ClamavDBVersion
		}
	}
	needUpdate := []scannermodel.ScanDBVersion{}
	if objType == scannermodel.TrivyDB {
		for k := range res {
			if res[k].KeyPath != scannermodel.MainScannerObject && res[k].VulnDBVersion.CompareVersion(mainVulnVer) {
				needUpdate = append(needUpdate, res[k])
			}
		}
	} else if objType == scannermodel.ClamavDB {
		for k := range res {
			if res[k].KeyPath != scannermodel.MainScannerObject && res[k].ClamavDBVersion.CompareVersion(mainMaliciousVer) {
				needUpdate = append(needUpdate, res[k])
			}
		}
	} else if objType == scannermodel.AviraDB {
		for k := range res {
			if res[k].KeyPath != scannermodel.MainScannerObject && res[k].AviraDBVersion.CompareVersion(mainMaliciousVer) {
				needUpdate = append(needUpdate, res[k])
			}
		}
	}
	return needUpdate, nil
}
func (v *DBManage) logUpdateHistory(ctx context.Context, updater string, dbName *string, dbType string, err error) {
	if *dbName == scannermodel.DefaultDBName || err != nil {
		return
	}
	history := scannermodel.ScanDBUpdateHistroy{ComPressDBVersion: *dbName, Updater: updater, DBType: dbType}
	history.UUID = history.GetUUID()
	if err != nil {
		history.Result = err.Error()
	}
	cErr := v.dal.CreateVersionHistory(ctx, history)
	if cErr != nil {
		logging.Get().Err(err).Msg("CreateVersionHistory error")
	}
}

func (v *DBManage) logVersionMata(ctx context.Context, matas []scannermodel.ScanDbMateData) {
	err := v.dal.CreateVersionMate(ctx, matas)
	if err != nil {
		logging.Get().Err(err).Msg("CreateVersionMate error")
	}
	return
}

func (v *DBManage) UpdateClamavDB(ctx *gin.Context, dbName *string, mata *scannermodel.ScanDbMateData, ver *scannermodel.MaliciousDBVersion) error {
	oldVer, err := scannermodel.ReadMaliciousDBVersion(filepath.Join(v.upSrv.PvcPath, scannermodel.ClamavVersionPath), scannermodel.ClamavDB)
	if err != nil {
		logging.Get().Warn().Msgf("read old version file err %v", err)
		return err
	}
	newVer, err := scannermodel.ReadMaliciousDBVersion(filepath.Join(v.upSrv.PvcPath, scannermodel.UnzipPath, scannermodel.ClamavVersionPath), scannermodel.ClamavDB)
	if err != nil {
		return fmt.Errorf("读取新版本文件失败 %v", err)
	}
	ok := v.upSrv.CheckMaliciousHash(ctx, newVer, filepath.Join(v.upSrv.PvcPath, scannermodel.UnzipPath))
	if !ok {
		return fmt.Errorf("文件hash对比失败与version文件不符 %v", err)
	}
	if newVer.Clamav.GetVersion() > oldVer.Clamav.GetVersion() {
		ok, err := v.upSrv.UpdateClamAvDB()
		if err != nil {
			return fmt.Errorf("更新clamav失败 %v", err)
		}
		if ok {
			oldVer.Clamav = newVer.Clamav
			mata.DBType = scannermodel.ClamavDB
			mata.DBMata = oldVer.Clamav.ClamavVersion
			*dbName = oldVer.Clamav.ComPressDBVersion
		}
	}
	*ver = oldVer
	return nil
}

func (v *DBManage) UpdateAviraDB(ctx *gin.Context, dbName *string, mata *scannermodel.ScanDbMateData, ver *scannermodel.MaliciousDBVersion) error {
	// oldVer, err := scannermodel.ReadMaliciousDBVersion(filepath.Join(v.upSrv.PvcPath, scannermodel.AviraVersionPath), scannermodel.AviraDB)
	// if err != nil {
	// 	logging.Get().Warn().Msgf("read old version file err %v", err)
	// }
	if os.Getenv("SCAN_VIRUS") != scannermodel.EnvAvira {
		return fmt.Errorf("当前病毒引擎不为avira")
	}
	newVer, err := scannermodel.ReadMaliciousDBVersion(filepath.Join(v.upSrv.PvcPath, scannermodel.UnzipPath, scannermodel.AviraVersionPath), scannermodel.AviraDB)
	if err != nil {
		return fmt.Errorf("读取新版本文件失败 %v", err)
	}

	_, err = v.upSrv.UpdateAvriaDB()
	if err != nil {
		return err
	}
	ver.Avira = newVer.Avira
	mata.DBType = scannermodel.AviraDB
	mata.DBMata = ver.Avira.AvriaVersion
	*dbName = ver.Avira.ComPressDBVersion

	return nil
}

func (v *DBManage) UpdateMaliciousDB(ctx *gin.Context, header *multipart.FileHeader, updater string, ops string) error {
	// if v.upSrv.MaliciousLock.TryLock() {
	// 	defer v.upSrv.MaliciousLock.Unlock()
	// } else {
	// 	return fmt.Errorf("版本更新中，请等待上个版本更新完")
	// }

	updateMate := scannermodel.ScanDbMateData{}
	matas := []scannermodel.ScanDbMateData{updateMate}
	defer v.logVersionMata(ctx, matas)
	err := ctx.SaveUploadedFile(header, filepath.Join(v.upSrv.PvcPath, scannermodel.DownMaliciousZip)) // scannermodel
	if err != nil {
		logging.Get().Err(err).Msgf("Save file fail")
		err = fmt.Errorf("存储离线包失败 %v", err)
		return err
	}
	err = vulnupdata.Unzip(filepath.Join(v.upSrv.PvcPath, scannermodel.DownMaliciousZip), filepath.Join(v.upSrv.PvcPath, scannermodel.UnzipPath, scannermodel.MaliciousDir))
	if err != nil {
		logging.Get().Err(err).Msgf("unzip error :%v", err)
		err = fmt.Errorf("解压离线包失败 %v", err)
		return err
	}
	oldVer := scannermodel.MaliciousDBVersion{}
	dbName := scannermodel.DefaultDBName
	defer v.logUpdateHistory(ctx, updater, &dbName, ops, err)

	toDB := scannermodel.ScanDBVersion{KeyPath: scannermodel.MainScannerObject} // scannermodel
	var reqType pb.ImageSecReqType
	if ops == scannermodel.ClamavDB {
		logging.Get().Info().Msg("update UpdateClamavDB")
		err = v.UpdateClamavDB(ctx, &dbName, &updateMate, &oldVer)
		if err != nil {
			logging.Get().Err(err).Msgf("update clamavDB error")
			err = fmt.Errorf("更新clamavDB失败")
			return err
		}
		reqType = pb.ImageSecReqType_ClamavDBUpdate
		toDB.ClamavDBVersion = oldVer.Clamav
		toDB.ClamavDBVersion.UpdateTime = time.Now().UnixMilli()
	} else if ops == scannermodel.AviraDB {
		err = v.UpdateAviraDB(ctx, &dbName, &updateMate, &oldVer)
		if err != nil {
			logging.Get().Err(err).Msgf("update aviraDB error")
			err = fmt.Errorf("更新aviraDB失败 %v", err)
			return err
		}
		reqType = pb.ImageSecReqType_AviraDBUpdate
		toDB.AviraDBVersion = oldVer.Avira
		toDB.AviraDBVersion.UpdateTime = time.Now().UnixMilli()
	} else {
		return fmt.Errorf("ops传参错误")
	}

	// 这一步是更新镜像中文件所保存的 version 信息
	err = v.upSrv.UpdateMaliciousVersion(oldVer, ops)
	if err != nil {
		logging.Get().Err(err).Msgf("update version to file error")
		err = fmt.Errorf("更新版本文件失败 %v", err)
		return err
	}
	// 保存数据库
	err = v.dal.UpdateVersion(ctx, toDB, ops)
	if err != nil {
		logging.Get().Err(err).Msgf("update version db error")
		err = fmt.Errorf("更新数据库失败 %v", err)
		return err
	}
	needUp, err := v.GetSubVersion(ctx, ops)
	logging.Get().Info().Msgf("need up is %v", needUp)
	if err != nil {
		logging.Get().Err(err).Msgf("get NeedUpdate Service from db error")
		err = fmt.Errorf("获取子集群版本列表失败 %v", err)
		return err
	}
	cli, err := stream.GetGrpcClient()
	if err != nil {
		logging.Get().Err(err).Msgf("get Grpc client error")
		err = fmt.Errorf("获取grpc链接失败 %v", err)
		return err
	}
	err = vulnupdata.Zip(scannermodel.PushMaliciousZip, v.upSrv.PvcPath, ops)
	if err != nil {
		logging.Get().Err(err).Msgf("zip db error")
		err = fmt.Errorf("打包db出错,主集群数据库已更新，子集群更新失败 %v", err)
		return err
	}
	payload, err := os.ReadFile(filepath.Join(v.upSrv.PvcPath, scannermodel.PushMaliciousZip))
	if err != nil {
		logging.Get().Err(err).Msgf("read zip db error")
		err = fmt.Errorf("读取DB出错 %v", err)
		return err
	}
	go func() {
		for k := range needUp {
			if needUp[k].KeyPath == "main" {
				continue
			}
			logging.Get().Info().Msgf("向console发送更新包,目标:%v", needUp[k].KeyPath)
			secReq := &pb.ImageSecReq{
				Payload:         payload,
				ImageSecDstPath: needUp[k].KeyPath,
				ImageSecReqType: reqType,
				ImageSecDstType: pb.ImageSecDstType_SubScanner,
			}
			key := strings.Split(needUp[k].KeyPath, "@")
			secReq.ClusterKey = key[0]
			secReq.NodeName = append(secReq.NodeName, key[1])
			if strings.Contains(key[1], "scanner") {
				secReq.ImageSecDstType = pb.ImageSecDstType_SubScanner
			}
			resp, err := cli.ScannerPushImageSecMsg(ctx, secReq)
			if err != nil {
				logging.Get().Err(err).Msgf("push db error key:%v", needUp[k].KeyPath)
				continue
			}
			if resp != nil {
				logging.Get().Info().Msgf("push db to console ok %v", resp.StatusMessage)
			}
		}
	}()
	return nil
}

func (v *DBManage) UpdateVulnDB(ctx *gin.Context, header *multipart.FileHeader, updater string) error {
	// if v.upSrv.VulnLock.TryLock() {
	// 	defer v.upSrv.VulnLock.Unlock()
	// } else {
	// 	return fmt.Errorf("版本更新中，请等待上个版本更新完")
	// }
	var dbName string
	dbName = scannermodel.DefaultDBName
	oldVer, err := scannermodel.ReadVulnDBVersion(filepath.Join(v.upSrv.PvcPath, scannermodel.VulnVersionPath))
	defer v.logUpdateHistory(ctx, updater, &dbName, scannermodel.TrivyDB, err)
	if err != nil {
		logging.Get().Err(err).Msg("read old version file err")
	}
	trivyMata := scannermodel.ScanDbMateData{DBMata: oldVer.TrivyVersion, DBType: scannermodel.TrivyDB}
	customMata := scannermodel.ScanDbMateData{DBMata: oldVer.CustomDBVersion, DBType: scannermodel.CustomDB}
	matas := []scannermodel.ScanDbMateData{trivyMata, customMata}
	defer v.logVersionMata(ctx, matas)
	err = ctx.SaveUploadedFile(header, filepath.Join(v.upSrv.PvcPath, scannermodel.DownVulnZip)) // scannermodel
	if err != nil {
		logging.Get().Err(err).Msgf("Save file fail")
		err = fmt.Errorf("存储离线包失败 %v", err)
		return err
	}
	err = vulnupdata.Unzip(filepath.Join(v.upSrv.PvcPath, scannermodel.DownVulnZip), filepath.Join(v.upSrv.PvcPath, scannermodel.UnzipPath))
	if err != nil {
		// os.Remove(filepath.Join(srv.VolumePath, "down.zip"))
		logging.Get().Err(err).Msgf("unzip error :%v", err)
		err = fmt.Errorf("解压离线包失败 %v", err)
		return err
	}
	newVer, err := scannermodel.ReadVulnDBVersion(filepath.Join(v.upSrv.PvcPath, scannermodel.UnzipPath, scannermodel.VulnVersionPath))
	if err != nil {
		logging.Get().Err(err).Msgf("read new version file err:%v", err)
		err = fmt.Errorf("读取新版本文件失败 %v", err)
		return err
	}
	dbName = newVer.ComPressDBVersion
	// add context
	ok := v.upSrv.CheckVulnHash(newVer, filepath.Join(v.upSrv.PvcPath, scannermodel.UnzipPath))
	if !ok {
		logging.Get().Err(err).Msgf("check db hash:%v", err)
		err = fmt.Errorf("文件hash对比失败与version文件不符 %v", err)
		return err
	}

	logging.Get().Info().Msgf("compare version %v %v", newVer.GetVersion(scannermodel.TrivyDB), oldVer.GetVersion(scannermodel.TrivyDB))

	if newVer.GetVersion(scannermodel.TrivyDB) > oldVer.GetVersion(scannermodel.TrivyDB) {
		ok, err := v.upSrv.UpdateVulnDB()
		if err != nil {
			logging.Get().Err(err).Msg("updateVulnDB error")
		}
		if ok {
			oldVer.TrivyVersion = newVer.TrivyVersion
			oldVer.ComPressDBVersion = newVer.ComPressDBVersion
			oldVer.UpdateTime = time.Now().UnixMilli()
		}
	}
	if newVer.GetVersion(scannermodel.CustomDB) > oldVer.GetVersion(scannermodel.CustomDB) {
		ok, err := v.upSrv.UpdateBoltDB()
		if err != nil {
			logging.Get().Err(err).Msg("updateBoltDB error")
		}
		if ok {
			oldVer.CustomDBVersion = newVer.CustomDBVersion
			oldVer.ComPressDBVersion = newVer.ComPressDBVersion
			oldVer.UpdateTime = time.Now().UnixMilli()
		}
	}
	err = v.upSrv.UpdateVulnVersion(oldVer)
	if err != nil {
		logging.Get().Err(err).Msgf("update version to file error")
		err = fmt.Errorf("更新版本文件失败 %v", err)
		return err
	}
	matas[0].DBMata = oldVer.TrivyVersion
	matas[1].DBMata = oldVer.CustomDBVersion
	toDB := scannermodel.ScanDBVersion{VulnDBVersion: oldVer, KeyPath: scannermodel.MainScannerObject} // scannermodel
	err = v.dal.UpdateVersion(ctx, toDB, scannermodel.TrivyDB)
	if err != nil {
		logging.Get().Err(err).Msgf("update version db error")
		err = fmt.Errorf("更新数据库失败 %v", err)
		return err
	}
	global.VulnDBVersion.VulnVersion = oldVer
	needUp, err := v.GetSubVersion(ctx, scannermodel.TrivyDB)
	logging.Get().Info().Msgf("need up is %v", needUp)
	if err != nil {
		logging.Get().Err(err).Msgf("get NeedUpdate Service from db error")
		err = fmt.Errorf("获取子集群版本列表失败 %v", err)
		return err
	}
	cli, err := stream.GetGrpcClient()
	if err != nil {
		logging.Get().Err(err).Msgf("get Grpc client error")
		err = fmt.Errorf("获取grpc链接失败 %v", err)
		return err
	}
	err = vulnupdata.Zip(scannermodel.PushVulnZip, v.upSrv.PvcPath, scannermodel.TrivyDB)
	if err != nil {
		logging.Get().Err(err).Msgf("zip db error")
		err = fmt.Errorf("打包db出错,主集群数据库已更新，子集群更新失败 %v", err)
		return err
	}
	payload, err := os.ReadFile(filepath.Join(v.upSrv.PvcPath, scannermodel.PushVulnZip))
	if err != nil {
		logging.Get().Err(err).Msgf("read zip db error")
		err = fmt.Errorf("读取DB出错 %v", err)
		return err
	}
	go func() {
		if r := recover(); r != nil {
			logging.Get().Error().Msgf("panic: %v. Stack: %s", r, debug.Stack())
		}

		for k := range needUp {
			if needUp[k].KeyPath == "main" {
				continue
			}
			logging.Get().Info().Msgf("向console发送更新包,目标:%v", needUp[k].KeyPath)
			secReq := &pb.ImageSecReq{
				Payload:         payload,
				ImageSecDstPath: needUp[k].KeyPath,
				ImageSecReqType: pb.ImageSecReqType_TiDBUpdate,
				ImageSecDstType: pb.ImageSecDstType_SubScanner,
			}
			key := strings.Split(needUp[k].KeyPath, "@")
			secReq.ClusterKey = key[0]
			secReq.NodeName = append(secReq.NodeName, key[1])
			if strings.Contains(key[1], "scanner") {
				secReq.ImageSecDstType = pb.ImageSecDstType_SubScanner
			}
			resp, err := cli.ScannerPushImageSecMsg(ctx, secReq)
			if err != nil {
				logging.Get().Err(err).Msgf("push db error key:%v", needUp[k].KeyPath)
				continue
			}
			if resp != nil {
				logging.Get().Info().Msgf("push db to console ok %v", resp.StatusMessage)
			}
		}
	}()

	// create task when vuln updater trigger scan enabled
	go func() {
		if r := recover(); r != nil {
			logging.Get().Error().Msgf("panic: %v. Stack: %s", r, debug.Stack())
		}
		_ = v.generateScanTask()
	}()

	go func() {
		if r := recover(); r != nil {
			logging.Get().Error().Msgf("addLibScanTask panic: %v. Stack: %s", r, debug.Stack())
		}
		_ = v.addLibScanTask()
	}()

	return nil
}

func (v *DBManage) addLibScanTask() error {
	if os.Getenv("IS_MAIN_CLUSTER") != consts.TrueString {
		logging.Get().Info().Msg("AddTaskByStrategy DBManage add scan task not in main cluster")
		return nil
	}
	// 增加扫描任务
	ts := task.NewTaskSrv()
	if err := ts.GenerateScanTask(context.Background(), nil, task.UpdateTaskInfo{
		Scope:       consts.FullScan,
		TriggerType: consts.VulDataUpdateTrigger,
	}); err != nil {
		logging.Get().Err(err).Msg("AddTaskByStrategy DBManage add scan task failed")
		return err
	}
	logging.Get().Info().Msgf("AddTaskByStrategy DBManage add scan task success")
	return nil
}

func (v *DBManage) GetDBVersion(ctx *gin.Context, search string) ([]scannermodel.VersionResp, error) {
	ver, _, err := v.dal.SearchVersion(ctx, store.SearchVersionParam{ClusterKey: scannermodel.MainScannerObject}, model.Filter{})
	if err != nil {
		logging.Get().Err(err).Msg("SearchVersion error")
		return nil, err
	}
	if len(ver) < 1 {
		return nil, fmt.Errorf("未查询到version数据")
	}
	res := make([]scannermodel.VersionResp, 0)
	trivyResp := scannermodel.VersionResp{CompressVersion: ver[0].VulnDBVersion.ComPressDBVersion,
		UpdateTime: ver[0].VulnDBVersion.UpdateTime, DBType: scannermodel.TrivyDB}
	clamavResp := scannermodel.VersionResp{CompressVersion: ver[0].ClamavDBVersion.ComPressDBVersion,
		UpdateTime: ver[0].ClamavDBVersion.UpdateTime, DBType: scannermodel.ClamavDB}
	aviraResp := scannermodel.VersionResp{CompressVersion: ver[0].AviraDBVersion.ComPressDBVersion,
		UpdateTime: ver[0].AviraDBVersion.UpdateTime, DBType: scannermodel.AviraDB}
	switch search {
	case scannermodel.TrivyDB:
		res = append(res, trivyResp)
	case scannermodel.ClamavDB:
		res = append(res, clamavResp)
	case scannermodel.AviraDB:
		res = append(res, aviraResp)
	default:
		res = append(res, trivyResp, clamavResp, aviraResp)
	}
	return res, nil
}

func (v *DBManage) GetHistory(ctx *gin.Context, search string, dbType string) ([]scannermodel.HistoryResp, error) {
	var dbTypes []string
	if dbType != "" {
		dbTypes = strings.Split(dbType, ",")
	}
	his, _, err := v.dal.SearchVersionHistory(ctx, store.SearchVersionHistoryParam{Search: search, DBType: dbTypes}, model.Filter{})
	if err != nil {
		logging.Get().Err(err).Msg("SearchVersionHistory error")
		return nil, err
	}
	res := make([]scannermodel.HistoryResp, 0)
	for k := range his {
		res = append(res, scannermodel.HistoryResp{CompressVersion: his[k].ComPressDBVersion, UpdateTime: his[k].UpdatedAt,
			Updater: his[k].Updater, DBType: his[k].DBType})
	}
	sort.SliceStable(res, func(i, j int) bool {
		return res[i].UpdateTime > res[j].UpdateTime
	})
	return res, nil
}

func (v *DBManage) generateScanTask() error {
	// query scan config
	scannerWrapperDb := store.GetScannerWrapperDb()
	scannerConfigDal := imagesecStore.NewScannerConfigDao(scannerWrapperDb)
	scanImageConfigSrv := imagesecSrv.NewScannerConfigSrv(scannerConfigDal)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	data, err := scanImageConfigSrv.GetScanImageConfig(ctx, imagesecModel.ConfigTypeNodeScanImage)
	if err != nil {
		logging.Get().Err(err).Msgf("failed to get scan image config,ignore create tasks by vuln update trigger")
		return err
	}

	if !data.NodeImageConfig.VulnFlush {
		logging.Get().Info().Msg("vuln update trigger scan task not enabled")
		return nil
	}

	// vuln trigger task enabled,generate scan task
	nodeScanTaskDal := imagesecStore.NewScanTaskDao(scannerWrapperDb)
	nodeImageDal := imagesecStore.NewImageMetaDao(scannerWrapperDb, nil)
	registryDal := store.NewRegistryDao(scannerWrapperDb)
	resourceDal := store.NewResourceDao(scannerWrapperDb)
	nodeReportDal := imagesecStore.NewNodeReportDao(scannerWrapperDb)
	policyDal := imagesecStore.NewDetectPolicyDao(scannerWrapperDb)
	detectResultDal := imagesecStore.NewImageDetectResultDao(scannerWrapperDb)
	nodeScanResultDal := imagesecStore.NewScanResultDao(scannerWrapperDb)
	trustedImageDal := store.NewScannerOrm(scannerWrapperDb)
	nodeImageSvc := imagemeta.NewNodeImageSrv(nodeImageDal, registryDal, nodeScanResultDal,
		resourceDal, nodeReportDal, policyDal,
		detectResultDal, trustedImageDal, scannerConfigDal, nodeScanTaskDal)
	detectTaskDal := imagesecStore.NewDetectTaskDao(scannerWrapperDb)
	scanTaskSrv := imagescan.NewScanTaskSrv(nodeScanTaskDal, detectTaskDal, nodeImageSvc, scannerConfigDal)
	param := imagesecModel.ImageListParam{
		ImageFromType: imagesecModel.ImageFromNode,
	}
	taskInfo := imagesecModel.ImageScanTask{
		ImageFromType: imagesecModel.ImageFromNode,
		ScanType:      imagesecModel.VulnDbUpdateTrigger,
		Status:        imagesecModel.TaskStatusNotReady,
		Updater:       imagesecModel.VulnDbUpdateTrigger,
		Creator:       imagesecModel.VulnDbUpdateTrigger,
	}
	if err := scanTaskSrv.CreateImageScanTask(context.Background(), param, taskInfo); err != nil {
		logging.Get().Err(err).Msg("failed to create tasks by vuln update trigger")
		return err
	}
	logging.Get().Info().Msg("create tasks by vuln update trigger ok")
	return nil
}
