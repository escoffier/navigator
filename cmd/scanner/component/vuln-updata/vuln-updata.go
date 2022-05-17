package vulnupdata

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/boltdb/bolt"
	"github.com/gin-gonic/gin"

	"github.com/yeka/zip"

	scanvuln "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scanner-vuln"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/task"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/vuln-updata/register"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/api/apikey"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/response"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type VulnUpdata struct {
	config register.Config
}

type UpdataService struct {
	VulnUpdatas          []VulnUpdata
	WantsToOfflineUpdata bool
	Cond                 *sync.Cond
	VolumePath           string
	Ch                   chan string
}

type VersionResp struct {
	Version string
	MD5     string
}

const (
	scannerUser = "tensorsec-cicd-user"
)

var (
	once              sync.Once
	scannerVulnUpdata *UpdataService
)

func (srv *UpdataService) AutoScanAll(ctx context.Context, fromType int64, operator string) error {
	if srv == nil {
		return fmt.Errorf("srv is nil")
	}
	dal := store.GetScannerOrmDb()
	scanConfigDal := store.GetScanConfigDao()
	if dal == nil || scanConfigDal == nil {
		return fmt.Errorf("can't get global dal")
	}

	config, cnt, err := scanConfigDal.SearchScanConfig(ctx, store.SearchScanConfigParam{}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msg("search scan config err")
		return err
	}
	if cnt == 0 || !config[0].VulnFlushTrigEnable {
		return nil
	}

	logging.GetLogger().Info().Int64("fromType", fromType).Msg("start full scan")
	// 先查询当前时刻已存在的仓库列表
	registries, _, err := dal.SearchRegistry(ctx, store.SearchRegistryParam{NoDelete: true}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msg("not found registry info")
		return err
	}
	registryIds := make([]int64, len(registries))
	for i := range registries {
		registryIds[i] = registries[i].ID
	}

	imgIds := make([]int64, 0)

	imgs, _, err := dal.SearchImage(ctx, store.SearchImageParam{FromType: fromType, RegistryIds: registryIds, Fields: []string{"id"}}, nil)
	if err != nil {
		logging.GetLogger().Err(err).Msg("query images error")
		return err
	}

	for i := range imgs {
		imgIds = append(imgIds, imgs[i].ID)
	}

	if len(imgIds) == 0 {
		logging.GetLogger().Info().Msg("full image scan not found match images")
		return nil
	}

	ts := task.NewTaskSrv()
	if err := ts.GenerateScanTask(ctx, imgIds, task.UpdateTaskInfo{TriggerType: consts.VulDataUpdateTrigger, Scope: consts.FullScan, Operator: operator}); err != nil {
		logging.GetLogger().Err(err).Msg("add full scan task failed")
		return err
	}
	logging.GetLogger().Info().Msg("add full scan task end")
	return nil
}

func (srv *UpdataService) cpDB(volumePath string, fromPath string, FileName string, dstName string) {
	osCMD := exec.Command("cp", "-f", filepath.Join(fromPath, FileName), filepath.Join(volumePath, dstName))
	err := osCMD.Run()
	if err != nil {
		logging.GetLogger().Err(err).Msgf("%s CP  err :%v", FileName, err)
	}
}
func FileExists(path string) bool {
	_, err := os.Stat(path) //os.Stat获取文件信息

	if err != nil {
		return os.IsExist(err)
	}

	return true
}

func CheckDb(dbPath string, bucketName string, opts bolt.Options) error {
	logging.GetLogger().Info().Str("dbPath", dbPath).Str("bucketName", bucketName).Msg("check db")
	if !FileExists(dbPath) {
		return fmt.Errorf("%v is not Exist", dbPath)
	}
	db, err := bolt.Open(dbPath, 0600, &opts)
	if err != nil {
		return err
	}
	defer db.Close()
	err = db.View(func(tx *bolt.Tx) error {
		testBucket := tx.Bucket([]byte(bucketName))
		if testBucket == nil {
			return fmt.Errorf("get %v Bucket failed", bucketName)
		}
		return nil
	})
	logging.GetLogger().Info().Msg("check end")
	return err
}

func (srv *UpdataService) GenerateDir(volumePath string) (string, error) {
	tmpDir, err := ioutil.TempDir("/root/", "")
	if err != nil {
		return "", err
	}
	fp := filepath.Join(tmpDir, "db")
	err = os.Mkdir(fp, 0666)
	if err != nil {
		os.Remove(tmpDir)
		return "", err
	}
	logging.GetLogger().Info().Str("dbPath", fp).Msg("generate dir")
	resVersion := srv.ReadVersion("trivy")
	dbPath := filepath.Join(srv.VolumePath, "last_trivy.db")
	if resVersion == "offline" {
		dbPath = filepath.Join(srv.VolumePath, "offline", "init_trivy.db")
	}
	osCMD := exec.Command("cp", "-f", dbPath, filepath.Join(fp, "/trivy.db"))
	err = osCMD.Run()
	if err != nil {
		logging.GetLogger().Err(err).Msgf(" CP  err :%v", err)
		return "", err
	}
	return tmpDir, nil
}

func (srv *UpdataService) InitUpdateSvc() {
	for {
		if srv.CheckList() {
			break
		} else {
			time.Sleep(time.Second * 10)
		}
	}
	if FileExists(srv.VolumePath + "last_custom.db") {
		srv.cpDB(srv.VolumePath, srv.VolumePath, "last_custom.db", "init_custom.db")
		srv.cpDB(srv.VolumePath, srv.VolumePath, "custom_version", "custom_init_version")
	} else {
		srv.cpDB(srv.VolumePath, srv.VolumePath, "init_custom.db", "last_custom.db")
		srv.cpDB(srv.VolumePath, srv.VolumePath, "custom_init_version", "custom_version")
	}

	if FileExists(srv.VolumePath + "last_trivy.db") {
		srv.cpDB(srv.VolumePath, srv.VolumePath, "last_trivy.db", "init_trivy.db")
		srv.cpDB(srv.VolumePath, srv.VolumePath, "trivy_version", "trivy_init_version")
	} else {
		srv.cpDB(srv.VolumePath, srv.VolumePath, "init_trivy.db", "last_trivy.db")
		srv.cpDB(srv.VolumePath, srv.VolumePath, "trivy_init_version", "trivy_version")
	}
	fp := filepath.Join(srv.VolumePath, "init_db", "db")
	err := os.MkdirAll(fp, 0777)
	if err != nil {
		logging.GetLogger().Err(err).Msg("mkdir err")
		return
	}
	res := srv.ReadVersion("trivy")
	if res != "offline" {
		srv.cpDB(fp+"/", srv.VolumePath, "last_trivy.db", "trivy.db")
	} else {
		srv.cpDB(fp+"/", filepath.Join(srv.VolumePath, "offline"), "init_trivy.db", "trivy.db")
	}
}

func (srv *UpdataService) Run(offline bool, volumePath string, ch chan<- string) {
	var options bolt.Options
	options.Timeout = time.Second * 5
	//如果不存在更新后版本，初始化一份last版本（避免bolt锁）
	logging.GetLogger().Info().Msg("IN Run")
	if !offline {
		var db *bolt.DB
		var err error

		//srv.VulnUpdatas, _ = NewVulnUpdata(context.Background(), "/configs/scanner/updata.yaml")
		srv.VulnUpdatas = GetRegisterUpdater()
		registers := []register.Registry{}
		ticker := time.NewTicker(time.Hour * 6)
		defer ticker.Stop()
		for {
			res := srv.ReadVersion("custom")
			if res == "offline" {
				srv.cpDB(srv.VolumePath, filepath.Join(srv.VolumePath, "offline"), "init_custom.db", "init_custom.db")
			}
			logging.GetLogger().Info().Msg("open init DB")
			db, err = bolt.Open(filepath.Join(volumePath, "init_custom.db"), 0600, &options)
			if err != nil {
				logging.GetLogger().Err(err).Msgf("Bolt Open Error %v", err)
				time.Sleep(time.Duration(100) * time.Second)
				continue
			}
			logging.GetLogger().Info().Msg("DB is ok")
			for k := range srv.VulnUpdatas {
				r := srv.VulnUpdatas[k].GetRegister(db, volumePath)
				registers = append(registers, r)
			}

			var wgg sync.WaitGroup
			for k := range registers {
				wgg.Add(1)
				go registers[k].Updata(&wgg)
			}
			wgg.Wait()
			db.Close()
			srv.WriteVersion()
			srv.cpDB(volumePath, volumePath, "init_custom.db", "last_custom.db") //更新的是init_custom.db
			srv.cpDB(volumePath, volumePath, "last_trivy.db", "init_trivy.db")   //需要读取的是init_trivy.db
			srv.cpDB(srv.VolumePath, srv.VolumePath, "trivy_version", "trivy_init_version")
			srv.cpDB(srv.VolumePath, srv.VolumePath, "custom_version", "custom_init_version")
			// srv.cpDB(volumePath, "/configs/scanner-vuln-updata/", "trivy_version", "trivy_version")

			filePath, err := srv.GenerateDir(volumePath)
			if err != nil {
				logging.GetLogger().Err(err).Msgf("GenerateDir err:%v", err)
				ch <- "err"
			} else {
				ch <- filePath
			}
			// err = srv.AutoScanAll(context.Background(), 1, "漏洞库更新触发")
			// if err != nil {
			// 	logging.GetLogger().Err(err).Msgf("vuln-updata ticker scanALL failed")
			// }
			<-ticker.C
		}
	}
	close(ch)
	//wg.Wait()
}

func (srv *UpdataService) ReadVersion(name string) string {
	res := "last"
	if strings.Contains(name, "trivy") {
		offlineVersion := ""
		trivyVersion := ""
		if FileExists(filepath.Join(srv.VolumePath, "trivy_version")) {
			trivyVersionBytes, err := os.ReadFile(filepath.Join(srv.VolumePath, "trivy_version"))
			if err != nil {
				logging.GetLogger().Err(err).Msgf("Open now Trivy version Error")
			} else {
				trivyVersion = string(trivyVersionBytes)
				res = "last"
			}
		}
		if FileExists(filepath.Join(srv.VolumePath, "offline", "trivy_init_version")) {
			offlineVersionBytes, err := os.ReadFile(filepath.Join(srv.VolumePath, "offline", "trivy_init_version"))
			if err != nil {
				logging.GetLogger().Err(err).Msgf("Open Offline Trivy version Error")
			} else {
				offlineVersion = string(offlineVersionBytes)
			}
		}
		if !CompareVersion("trivy", trivyVersion, offlineVersion) {
			res = "offline"
		}
	} else if strings.Contains(name, "custom") {
		offlineVersion := "2006-01-02 15:04:05"
		CustomVersion := ""
		if util.FileExists(filepath.Join(srv.VolumePath, "custom_version")) {
			CustomVersionBytes, err := os.ReadFile(filepath.Join(srv.VolumePath, "custom_version"))
			if err != nil {
				logging.GetLogger().Err(err).Msgf("Open now Custom version Error")
				CustomVersion = "2006-01-02 15:04:05"
			} else {
				CustomVersion = string(CustomVersionBytes)
				res = "last"
			}
		}
		if util.FileExists(filepath.Join(srv.VolumePath, "offline", "custom_init_version")) {
			CustomVersionBytes, err := os.ReadFile(filepath.Join(srv.VolumePath, "offline", "custom_init_version"))
			if err != nil {
				logging.GetLogger().Err(err).Msgf("Open Offline Custom version Error")
			} else {
				offlineVersion = string(CustomVersionBytes)
			}
		}
		if !CompareVersion("custom", CustomVersion, offlineVersion) {
			res = "offline"
		}
	}
	logging.GetLogger().Info().Msgf("Download res :%v", res)
	return res
}

func (srv *UpdataService) WriteVersion() {
	filename := filepath.Join(srv.VolumePath, "custom_version")
	t := time.Now()
	version := t.Format("2006-01-02 15:04:05")
	file, err := os.OpenFile(filename, os.O_RDWR|os.O_TRUNC|os.O_CREATE, 0666)
	if err != nil {
		return
	}
	defer file.Close()
	fmt.Fprintf(file, "%s", version)
}

func GetUpdataService() *UpdataService {
	return scannerVulnUpdata
}

func NewUpdataService(volumePath string, ch chan string) *UpdataService {
	once.Do(func() {
		m := sync.Mutex{}
		c := sync.NewCond(&m)
		scannerVulnUpdata = &UpdataService{}
		scannerVulnUpdata.Cond = c
		scannerVulnUpdata.VolumePath = volumePath
		scannerVulnUpdata.Ch = ch
	})
	return scannerVulnUpdata
}

// func (srv *UpdataService) SetUpRouter() *gin.Engine {
// 	router := gin.Default()
// 	router.Use(gin.Logger(), gin.Recovery())
// 	//router.Static("/download", "/tmp/download")
// 	router.GET("/download/:name", srv.fileServer)
// 	router.GET("/query/version/:name", srv.queryVersion)
// 	router.PUT("/VulnDb", srv.UploadOffline)
// 	return router
// }

func UploadOffline(c *gin.Context) {
	logging.GetLogger().Info().Msgf("IN UploadOffline")
	key := c.Request.Header.Get("X-Tensorsec-cicd-key")
	valid, err := apikey.ValidateApiKey(key, scannerUser)
	if err != nil || !valid {
		logging.GetLogger().Err(err).Msgf("invalid ci/cd api key %v", err)
		response.JSONError(c, fmt.Errorf("invalid key"))
		return
	}
	header, err := c.FormFile("file")
	if err != nil {
		logging.GetLogger().Err(err).Msgf("ParseMultipartForm fail")
		response.JSONError(c, fmt.Errorf("解析MultipartForm失败"))
		return
	}
	err = c.SaveUploadedFile(header, filepath.Join(scannerVulnUpdata.VolumePath, "down.zip"))
	if err != nil {
		logging.GetLogger().Err(err).Msgf("Save file fail")
		response.JSONError(c, fmt.Errorf("存储离线包失败"))
		return
	}
	err = Unzip(filepath.Join(scannerVulnUpdata.VolumePath, "down.zip"), filepath.Join(scannerVulnUpdata.VolumePath, "offline/"))
	if err != nil {
		// os.Remove(filepath.Join(srv.VolumePath, "down.zip"))
		logging.GetLogger().Err(err).Msgf("unzip error :%v", err)
		response.JSONError(c, fmt.Errorf("存储离线包失败"))
		return
	}
	filePath, err := scannerVulnUpdata.GenerateDir(scannerVulnUpdata.VolumePath)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("gennerate Dir err:%v", err)
		response.JSONError(c, fmt.Errorf("更新流程失败"))
		return
	}
	scannerVulnUpdata.Ch <- filePath
	vuln := scanvuln.GetScannerVuln()
	err = vuln.InitDB()
	if err != nil {
		logging.GetLogger().Err(err).Msgf("init db err :%v", err)
		response.JSONError(c, fmt.Errorf("更新漏洞库成功，中文库失败"))
		return
	}
	err = scannerVulnUpdata.AutoScanAll(c, 1, "离线更新成功后自动触发")
	if err != nil {
		logging.GetLogger().Err(err).Msgf("scanall error :%v", err)
		response.JSONError(c, fmt.Errorf("更新漏洞库成功，触发全量扫描失败"))
		return
	}
	response.JSONOK(c)
}

// func (srv *UpdataService) fileServer(c *gin.Context) {
//	path := srv.VolumePath
//	fileName := path + c.Param("name")
//	if strings.Contains(fileName, "trivy") {
//		res := srv.ReadVersion("trivy")
//		if res == "init" {
//			c.File(srv.VolumePath + "init_trivy.db")
//		} else if res == "last" {
//			c.File(srv.VolumePath + "last_trivy.db")
//		} else if res == "offline" {
//			c.File(srv.VolumePath + "offline/init_trivy.db")
//		}
//	} else if strings.Contains(fileName, "custom") {
//		res := srv.ReadVersion("custom")
//		if res == "init" {
//			c.File(srv.VolumePath + "init_custom.db")
//		} else if res == "last" {
//			c.File(srv.VolumePath + "last_custom.db")
//		} else if res == "offline" {
//			c.File(srv.VolumePath + "offline/init_custom.db")
//		}
//	}
//}

//func (srv *UpdataService) queryVersion(c *gin.Context) {
//	res := VersionResp{}
//	name := c.Param("name")
//
//	if strings.Contains(name, "trivy") {
//		versionRes := srv.ReadVersion("trivy")
//		versionPath := ""
//		dbPath := ""
//		if versionRes == "init" {
//			versionPath = srv.VolumePath + "trivy_init_version"
//			dbPath = srv.VolumePath + "init_trivy.db"
//		} else if versionRes == "last" {
//			versionPath = srv.VolumePath + "trivy_version"
//			dbPath = srv.VolumePath + "last_trivy.db"
//		} else if versionRes == "offline" {
//			versionPath = srv.VolumePath + "offline/trivy_init_version"
//			dbPath = srv.VolumePath + "offline/init_trivy.db"
//		}
//		if versionPath != "" {
//			versionByte, _ := os.ReadFile(versionPath)
//			res.Version = string(versionByte)
//			res.MD5 = md5sum3(dbPath)
//		}
//	} else if strings.Contains(name, "custom") {
//		versionRes := srv.ReadVersion("custom")
//		versionPath := ""
//		dbPath := ""
//		if versionRes == "init" {
//			versionPath = srv.VolumePath + "custom_init_version"
//			dbPath = srv.VolumePath + "init_custom.db"
//		} else if versionRes == "last" {
//			versionPath = srv.VolumePath + "custom_version"
//			dbPath = srv.VolumePath + "last_custom.db"
//		} else if versionRes == "offline" {
//			versionPath = srv.VolumePath + "offline/custom_init_version"
//			dbPath = srv.VolumePath + "offline/init_custom.db"
//		}
//		if versionPath != "" {
//			versionByte, _ := os.ReadFile(versionPath)
//			res.Version = string(versionByte)
//			res.MD5 = md5sum3(dbPath)
//		}
//	}
//
//	//fmt.Println(strings.TrimSpace(res.Version) + "abcd")
//	//fmt.Println(res.MD5 + "jianbo")
//	c.String(200, "%s %s", strings.TrimSpace(res.Version), res.MD5)
//}

func NewVulnUpdata(ctx context.Context, configPath string) ([]VulnUpdata, error) {
	config, err := register.LoadConfig(configPath)
	if err != nil {
		logging.GetLogger().Fatal().Msg(fmt.Sprintf("failed to load configuration,configPath:%s,error:%s", configPath, err.Error()))
		return nil, err
	}
	var res []VulnUpdata
	for i := range config {
		tmpVulnUpdata := VulnUpdata{config: config[i]}
		res = append(res, tmpVulnUpdata)
	}
	return res, nil
}

func GetRegisterUpdater() []VulnUpdata {
	names := register.GetDriversName()
	vus := make([]VulnUpdata, 0)
	for _, v := range names {
		v := VulnUpdata{config: register.Config{
			Registry: register.RegistrableComponentConfig{
				Type: v,
			},
		}}
		vus = append(vus, v)
	}
	return vus
}

func (v *VulnUpdata) GetRegister(db *bolt.DB, dbPath string) register.Registry {
	// Open registry
	r, err := register.Open(v.config.Registry, db, dbPath)
	if err != nil {
		logging.GetLogger().Err(err).Msg("VulnUpdata load config err")
		return nil
	}
	return r
}

func (srv *UpdataService) CheckList() bool {
	fileList := []string{"init_trivy.db", "init_custom.db", "custom_init_version", "trivy_init_version"}
	for k := range fileList {
		if !FileExists(filepath.Join(srv.VolumePath, fileList[k])) {
			logging.GetLogger().Info().Msgf("File %v not exist while sleep 10S", srv.VolumePath+fileList[k])
			return false
		}
	}
	return true
}

//func md5sum3(file string) string {
//	f, err := os.Open(file)
//	if err != nil {
//		return ""
//	}
//	defer f.Close()
//	r := bufio.NewReader(f)
//
//	h := md5.New()
//
//	_, err = io.Copy(h, r)
//	if err != nil {
//		return ""
//	}
//
//	return fmt.Sprintf("%x", h.Sum(nil))
//
//}

func Unzip(zipFile string, destDir string) error {
	zipReader, err := zip.OpenReader(zipFile)
	if err != nil {
		return err
	}
	defer zipReader.Close()

	for _, f := range zipReader.File {
		if f.IsEncrypted() {
			f.SetPassword("tanzhen2020scanner")
		}
		fpath := filepath.Join(destDir, f.Name)
		if f.FileInfo().IsDir() {
			err = os.MkdirAll(fpath, os.ModePerm)
			if err != nil {
				return err
			}
		} else {
			if err = os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
				return err
			}

			inFile, err := f.Open()
			if err != nil {
				return err
			}

			outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
			if err != nil {
				inFile.Close()
				return err
			}

			_, err = io.Copy(outFile, inFile)
			inFile.Close()
			outFile.Close()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func CompareVersion(vtype string, old string, new string) bool {
	logging.GetLogger().Info().Msgf("CompareVersion New:%v old %v", new, old)
	if len(new) < 4 || len(old) < 4 {
		return true
	}
	if strings.Contains(vtype, "trivy") {
		old = old[3:]
		new = new[3:]
		old = strings.TrimSpace(old)
		new = strings.TrimSpace(new)
		logging.GetLogger().Info().Msgf("CompareVersion old :%v new:%v", old, new)
		oldNum, err := strconv.Atoi(old)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("old version Atoi failed when CompareVersion")
		}
		newNum, err := strconv.Atoi(new)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("new version Atoi failed when CompareVersion")
		}
		return oldNum > newNum
	} else if strings.Contains(vtype, "custom") {

		timeLayout := "2006-01-02 15:04:05"
		oldTime, _ := time.ParseInLocation(timeLayout, strings.TrimRight(old, "\n"), time.Local)
		newTime, _ := time.ParseInLocation(timeLayout, strings.TrimRight(new, "\n"), time.Local)
		oldTimeUnix := oldTime.Unix()
		newTimeUnix := newTime.Unix()
		logging.GetLogger().Info().Msgf("CompareVersion old :%v new:%v", oldTimeUnix, newTimeUnix)
		return oldTimeUnix > newTimeUnix
	}
	return true
}
