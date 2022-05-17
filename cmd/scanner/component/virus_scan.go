package component

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	dockerarchive "github.com/docker/docker/pkg/archive"
	"github.com/go-redis/redis/v8"
	"github.com/heroku/docker-registry-client/registry"
	layerManage "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/layer-manage"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/logging"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type VirusScan struct {
	ctx              context.Context
	mongodb          *mongo.Database
	postgresSvc      *store.ScannerDB
	redisClient      *redis.Client
	redisClientShare *redis.Client
	scanTasksChan    chan model.VirusScanTask
	cicdTasksChan    chan model.VirusScanTask
	numWorkers       int
	statusQueue      sync.Map
	webshellAddr     string
}

const (
	virusScanOneTimeout = time.Minute * 15
	virusSingleScore    = 40.0
	webshellNineToTen   = 40.0
	webshellSixToEight  = 30.0
	webshellFourToFive  = 20.0
)

func NewViursScanService(ctx context.Context, clairOpts *flag.ClairOpts, db *mongo.Database, postgresSvc *store.ScannerDB, rc *redis.Client, rcs *redis.Client, updateOpts *flag.UpdateOpts, webshellAddr string) (*VirusScan, error) {
	return &VirusScan{
		ctx:              ctx,
		mongodb:          db,
		postgresSvc:      postgresSvc,
		redisClient:      rc,
		redisClientShare: rcs,
		scanTasksChan:    make(chan model.VirusScanTask, 1000),
		cicdTasksChan:    make(chan model.VirusScanTask, 10),
		numWorkers:       clairOpts.NumWorkers,
		statusQueue:      sync.Map{},
		webshellAddr:     fmt.Sprintf("%s/v1/php/detector", webshellAddr),
	}, nil
}

func (virusScan *VirusScan) failDanglingTasks(ctx context.Context) error {
	// why do we need this function?
	//
	// If Scanner crashes and restarts, but there were 10 scantasks 'inprogress',
	// then Harbor will keep asking Console about the status of those 10 tasks. However,
	// the newly-restarted Scanner won't know about the 10 'inprogress' scantasks.
	// Harbor will keep asking Console for a long time. Harbor won't send any new scan requests.
	// As a result, new scans are not started until Console 'last chance' scan timeout happens.
	//
	// If Scanner crashes and restarts, Scanner could query mongo to get any 'inprogress' tasks and
	// restart those tasks. However, if there is some image that caused the Scanner crash
	// in the first place, then Scanner will keep crashing in a loop.
	// It's better to fail all 'inprogress' scantasks so that Scanner is not in inifinite crash loop.
	// Harbor retries a scan 3 times per image, so there is no risk of infinite loop.
	//
	// Alternatively, we need better restart logic.
	//
	// Note: this only works if we only have 1 instance of scanner running.
	//       Need to fix this logic when we want to scale or have HA.

	filter := bson.M{"status": model.VirusScanDoing}
	update := bson.M{
		"$set": bson.M{
			"status": model.ScanStatusFailed,
		},
	}

	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, time.Second*10)
	defer mongoCtxCancel()

	result, err := virusScan.mongodb.Collection(model.VirusScanTaskCollection.String()).UpdateMany(mongoCtx, filter, update)
	if err != nil {
		return apperror.NewMongoError(http.StatusInternalServerError, fmt.Errorf("Orphan collection - cursor error: %w", err))
	}

	logging.Get().Info().
		Int64("MatchedCount", result.MatchedCount).
		Int64("ModifiedCount", result.ModifiedCount).
		Int64("UpsertedCount", result.UpsertedCount).
		Msg("Maked inprogress scantasks as failed")

	return nil
}

func (virusScan *VirusScan) Run(ctx context.Context, llms *layerManage.LocalLayerManageSrv) error {
	// TODO FailTaskRestart
	err := virusScan.failDanglingTasks(ctx)
	if err != nil {
		logging.Get().Err(err).Msg("virusScan failDanglingTasks error")
	}

	var wg sync.WaitGroup
	err = os.Mkdir("/tmpscan", 0777)
	if err != nil {
		logging.Get().Err(err).Msgf("virusScan Mkdir error")
		return err
	}
	for i := 0; i < virusScan.numWorkers; i++ {
		wg.Add(1)
		go virusScan.workerRun(ctx, i, &wg, llms)
	}
	wg.Wait()
	logging.Get().Info().Msg("All VirusScan workers finished")
	return nil
}

func (virusScan *VirusScan) clamavScan(ctx context.Context, scanPath string, digestNum string) ([]model.VirusInfo, error) {

	// clamLogFile, err := ioutil.TempFile("/tmpscan/", "log")
	clamLogPath := scanPath[0:len(scanPath)-1] + ".log"
	cmd := exec.Command("/usr/bin/clamdscan", "--quiet", "-m", scanPath, "-l", clamLogPath)
	defer os.Remove(clamLogPath)
	// defer os.RemoveAll("/tmpscan/" + digestNum + "/")
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		// 扫描到病毒时err返回值为1,所以不能退出,错误时ParseSummrylogs读不到日志文件，会返回空集。
		errString := fmt.Sprintf("%s", err)
		if strings.Compare("exit status 1", errString) != 0 {
			logging.Get().Info().Err(err).Str("Out:", out.String()).Str("Stderr:", stderr.String()).Str("ScanPath:", scanPath).Msg("Cla ERROR")
			return []model.VirusInfo{}, fmt.Errorf("ClamScan Error %w", err)
		}
		// os.Remove("/configs/" + digestMy + "layer.tar")
		// return []model.ClamAvVirus{}
	}

	logging.Get().Info().Msg("Clamscan ok")
	VirusInfos := virusScan.ParseSummrylogs(clamLogPath, scanPath)
	// defer os.Remove(clamLogPath)
	// defer os.RemoveAll("/tmpscan/" + digestNum + "/")
	return VirusInfos, nil
}

func (virusScan *VirusScan) ParseSummrylogs(logPath string, scanPath string) []model.VirusInfo {
	replaceString := scanPath[0 : len(scanPath)-1]
	ClamAvVirus := []model.VirusInfo{}
	reader, err := ioutil.ReadFile(logPath)
	if err != nil {
		return []model.VirusInfo{}
	}
	str := (*string)(unsafe.Pointer(&reader))
	strSplit := strings.Split(*str, "\n")
	for _, val := range strSplit {
		tmp := strings.Index(val, "FOUND")
		if tmp != -1 {
			tmpResult := strings.Split(val[0:tmp-1], ":")
			if len(tmpResult) < 2 {
				continue
			}
			fileName := tmpResult[0][strings.LastIndex(tmpResult[0], "/")+1:]
			ClamAvVirus = append(ClamAvVirus, model.VirusInfo{FileName: fileName, FilePath: strings.Replace(tmpResult[0], replaceString, "", 1), VirusName: tmpResult[1]})
		}
		//tmp = strings.Index(val, "Infected files")
		/*if tmp != -1 {
			tmpbyte := val[16:]
			inFectedCount, _ = strconv.Atoi(tmpbyte)
		}*/
	}
	return ClamAvVirus
}

// 解析&过滤layer.tar中的文件
func (virusScan *VirusScan) parseLayerTar(tarFileName string, dst string, ch chan<- *fileContent) (uint64, error) {
	defer func() { close(ch) }() // close the channel
	tarFile, err := os.Open(tarFileName)
	if err != nil {
		return 0, fmt.Errorf("Failed to advance tarReader: %w", err)
	}
	defer func() { _ = tarFile.Close() }() // close the file

	decompressStreamReader, err := dockerarchive.DecompressStream(tarFile)
	if err != nil {
		return 0, fmt.Errorf("Failed to DecompressStream: %w", err)
	}

	defer func() { _ = decompressStreamReader.Close() }() // close the decompressStreamReader

	tarReader := tar.NewReader(decompressStreamReader)
	var count uint64 = 0
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return count, fmt.Errorf("Failed to advance tarReader: %w", err)
		}

		// 检查类型，过滤文件夹、软链接和硬链接
		switch header.Typeflag {
		case tar.TypeDir, tar.TypeLink, tar.TypeSymlink:
			continue
		}
		// fmt.Println(header.Name)
		perm := header.FileInfo().Mode().Perm()
		f := perm & os.FileMode(73)

		// 判断文件是否是可执行文件或者webshell后缀的文件
		if isExecute, isWebshell := uint32(f) == uint32(73), webshellFileExt(filepath.Ext(header.Name)); isExecute || isWebshell {
			// 这里这样写防止ioutil.ReadAll读取所有的内容
			if isExecute && !isWebshell {
				file, _ := virusScan.createFile(dst + header.Name)
				_, err := io.Copy(file, tarReader)
				if err != nil {
					logging.Get().Err(err).Msg("virusScan io.Copy error ")
				}
				err = os.Chmod(dst+header.Name, 0666)
				if err != nil {
					logging.Get().Err(err).Msg("virusScan os.Chmod error")
				}
				count++
			} else {
				content, err := ioutil.ReadAll(tarReader)
				if err != nil {
					continue
				}

				// 可执行文件，用于检测病毒
				if isExecute {
					file, _ := virusScan.createFile(dst + header.Name)
					_, err := io.Copy(file, tarReader)
					if err != nil {
						logging.Get().Err(err).Msg("virusScan io.Copy error")
					}
					err = os.Chmod(dst+header.Name, 0666)
					if err != nil {
						logging.Get().Err(err).Msg("virusScan os.Chmod error")
					}
					count++
				}

				// php文件，检测webshell
				if isWebshell {
					ch <- &fileContent{fileName: header.Name, reader: bytes.NewReader(content)}
				}
			}
		}
	}
	return count, nil
}

func (virusScan *VirusScan) createFile(name string) (*os.File, error) {
	err := os.MkdirAll(string([]rune(name)[0:strings.LastIndex(name, "/")]), 0755)
	if err != nil {
		return nil, err
	}
	return os.Create(name)
}

func (virusScan *VirusScan) AddScanTask(task model.VirusScanTask, comeFrom int) {
	virusScan.statusQueue.Store(task.ImageDigest, model.VirusScanQueueInfo{Status: model.VirusScanWait, StartAt: time.Now()}) // 加入状态缓存
	switch comeFrom {
	case consts.ScanTaskComeFromCICD:
		virusScan.cicdTasksChan <- task
	default:
		virusScan.scanTasksChan <- task
	}
}

func (virusScan *VirusScan) workerRun(ctx context.Context, id int, wg *sync.WaitGroup, llms *layerManage.LocalLayerManageSrv) {
	defer wg.Done()

	workerSublogger := logging.Get().With().Int("worker-id", id).Logger()
	ctx = workerSublogger.WithContext(ctx)

	logging.Get().Info().Msg("Started ViursScan worker")
loop:
	for {
		select {
		case scanTask := <-virusScan.cicdTasksChan:
			logging.Get().Info().Msg("Received CICD VirusScan task")
			virusScan.processScanTask(ctx, scanTask, llms)
			logging.Get().Info().Msg("Finish CICD VirusScan task")

		case scanTask := <-virusScan.scanTasksChan:
		priority:
			for {
				select {
				case scanTask := <-virusScan.cicdTasksChan:
					virusScan.processScanTask(ctx, scanTask, llms)
				default:
					break priority
				}
			}
			logging.Get().Info().Msg("Received VirusScan task")
			virusScan.processScanTask(ctx, scanTask, llms)
			logging.Get().Info().Msg("Finish VirusScan task")
		case <-ctx.Done():
			break loop
		}
	}
	logging.Get().Info().Msg("Shutting down VirusScan worker")
}

func (virusScan *VirusScan) processScanTask(ctx context.Context, scanTask model.VirusScanTask, llms *layerManage.LocalLayerManageSrv) {
	scanCtx, scanCtxCancel := context.WithTimeout(ctx, virusScanOneTimeout)
	defer scanCtxCancel()
	defer virusScan.statusQueue.Delete(scanTask.ImageDigest) // 删除状态缓存
	logging.Get().Info().
		Str("ID", scanTask.ID.Hex()).
		Str("URL", scanTask.URL).
		Str("Repository", scanTask.Repository).
		Str("Tag", scanTask.Tag).
		Str("ImageDigest", scanTask.ImageDigest).
		Msg("Starting to process VirusScan task")

	username := ""
	password := ""
	if scanTask.Authorization != "" {
		var err error
		username, password, err = virusScan.decodeUsernamePassword(scanTask)
		if err != nil {
			virusScan.logAndUpdateMongoStatus(ctx, scanTask, model.ScanStatusFailed, "Couldn't decode username and password", err, false)
			return
		}
	}

	hub, err := registry.New(scanTask.URL, username, password)
	if err != nil {
		// seems like error Golang's x509 package doesn't support error wrapping API yet:
		// https://github.com/golang/go/issues/30322
		// var hostnameErr *x509.HostnameError
		// if errors.As(err, &hostnameErr) { ... }
		// Therefore we must unwrap the error from HTTP package manually and try to cast

		// Check for any type of error defined in x509 package.
		_, ok1 := errors.Unwrap(err).(x509.SystemRootsError)
		_, ok2 := errors.Unwrap(err).(x509.CertificateInvalidError)
		_, ok3 := errors.Unwrap(err).(x509.UnknownAuthorityError)
		_, ok4 := errors.Unwrap(err).(x509.HostnameError)
		if ok1 || ok2 || ok3 || ok4 {
			logging.Get().Warn().Err(err).Msg("Certificate validation failed, but insecure option is on - will retry and skip TLS cert verification")
			hub, err = registry.NewInsecure(scanTask.URL, username, password)
		}
	}
	if err != nil {
		virusScan.logAndUpdateMongoStatus(ctx, scanTask, model.ScanStatusFailed, "Couldn't initialize docker registry client", err, false)
		return
	}

	// TODO: Should we allow for v1?
	version := "v2"
	layers, err := virusScan.readManifest(ctx, version, hub, scanTask)
	if err != nil {
		virusScan.logAndUpdateMongoStatus(ctx, scanTask, model.ScanStatusFailed, "Couldn't read manifest", err, false)
		return
	}
	virusScan.statusQueue.Store(scanTask.ImageDigest, model.VirusScanQueueInfo{Status: model.VirusScanDoing, StartAt: time.Now()}) // 更新状态缓存
	currentlyCachedLayers, toScan, err := virusScan.getCachedGraph(ctx, layers, scanTask)
	if err != nil {
		// rcSvc.logAndUpdateMongoStatus(ctx, scanTask, model.ScanStatusFailed, "Couldn't get cache graph", err)
		virusScan.logAndUpdateMongoStatus(ctx, scanTask, model.ScanStatusFailed, "Couldn't get cache graph", err, false)
		return
	}
	client, err := layerManage.NewLocalLayerManageClient(llms)
	if err != nil {
		logging.Get().Err(err).Msg("LLMS CLIENT NEW FAULT")
		virusScan.logAndUpdateMongoStatus(ctx, scanTask, model.ScanStatusFailed, "Couldn't get LLMS Client", err, false)
		return
	}
	for i := range toScan {
		err := virusScan.virusProcessLayer(scanCtx, hub, scanTask, &currentlyCachedLayers, toScan[i], client)
		if err != nil {
			logging.Get().Err(err).Msgf("VirusScan get ToScan error")
		}
	}
	logging.Get().Info().Msg("Virus scan finished, processed all layers")

	report := &model.VirusScanReport{}
	virus := make([]model.VirusInfo, 0)
	var webshell []model.WebShellInfo
	perLayerReport := make([]model.VirusLayerReport, 0)

	for layerNo, digest := range layers {

		cachedLayer, err := virusScan.getCachedEntry(scanCtx, digest, currentlyCachedLayers)
		if err != nil {
			cachedLayer = currentlyCachedLayers[digest]
		}

		perLayerReport = append(perLayerReport, model.VirusLayerReport{
			LayerNo:      layerNo,
			LayerDigest:  digest,
			ViursInfo:    cachedLayer.ScanReport.Virus,
			WebShellInfo: cachedLayer.ScanReport.Webshells,
		})
		virus = append(virus, cachedLayer.ScanReport.Virus...)

		webshell = append(webshell, cachedLayer.ScanReport.Webshells...)
	}
	report.Virus = model.VirusReport{
		Repository:     scanTask.Repository,
		Tag:            scanTask.Tag,
		Digest:         scanTask.ImageDigest,
		Virus:          virus,
		WebShellInfo:   webshell,
		PerLayerReport: perLayerReport,
	}
	scanTask.ScanReport = *report
	// flag := false
	// if len(virus) != 0 {
	//	flag = true
	// }
	// err = virusScan.logAndUpdateMongoStatus(ctx, scanTask, model.ScanStatusSucceeded, "", nil, flag)
	virusScan.updateRiskVirusCacheEntry(ctx, scanTask)
	virusScan.logToLayer(ctx, scanTask, scanTask.ImageID)
	virusScan.logPostgres(ctx, scanTask, scanTask.TableID)
	/*if err != nil {
		logging.Get().Err(err).Msg("Update Mongo Dockument Failed")
		return
	}*/
	logging.Get().Info().Msg("Processing of VirusScan task finished")
}

func (virusScan *VirusScan) logToLayer(ctx context.Context, scanTask model.VirusScanTask, ImageID int64) {
	for _, v := range scanTask.ScanReport.Virus.PerLayerReport {
		virusRes := make([]model.Malicious, 0, len(v.ViursInfo))
		tmpScanLayer := model.ScanLayer{}
		tmpScanLayer.LayerDigest = v.LayerDigest
		tmpScanLayer.ImageID = ImageID
		for _, virus := range v.ViursInfo {
			tmpMalicious := model.Malicious{}
			tmpMalicious.VirusInfo = virus
			virusRes = append(virusRes, tmpMalicious)
		}
		if len(virusRes) != 0 {
			tmpScanLayer.MaliciousInfoJSON, _ = json.Marshal(virusRes)
		}

		webshellRes := make([]model.Webshell, 0, len(v.WebShellInfo))

		for _, webshell := range v.WebShellInfo {
			tmpWebshell := model.Webshell{}
			tmpWebshell.WebShellInfo = webshell
			webshellRes = append(webshellRes, tmpWebshell)
		}

		if len(webshellRes) != 0 {
			tmpScanLayer.WebshellInfoJSON, _ = json.Marshal(webshellRes)
		}

		virusScan.postgresSvc.InsertVirusLayer(ctx, tmpScanLayer)
	}
}

func (virusScan *VirusScan) logPostgres(ctx context.Context, scanTask model.VirusScanTask, tableID int64) {
	scanImage := model.ScanImage{}

	virus := make([]model.Malicious, 0, len(scanTask.ScanReport.Virus.Virus))
	for _, v := range scanTask.ScanReport.Virus.Virus {
		tmp := model.Malicious{}
		tmp.VirusInfo = v
		virus = append(virus, tmp)
	}

	if len(virus) != 0 {
		scanImage.MaliciousInfoJSON, _ = json.Marshal(virus)
		scanImage.VirusScore = virusSingleScore
	}

	webshell := make([]model.Webshell, 0, len(scanTask.ScanReport.Virus.WebShellInfo))
	webshellFlag := 0 //2 4 and 8
	for _, v := range scanTask.ScanReport.Virus.WebShellInfo {
		scanImage.WebshellScore += calculateWebshellScore(v, &webshellFlag)
		tmp := model.Webshell{WebShellInfo: v}
		webshell = append(webshell, tmp)
	}
	scanImage.WebshellScore = math.Min(40, scanImage.WebshellScore)
	if len(webshell) != 0 {
		scanImage.WebshellInfoJSON, _ = json.Marshal(webshell)
	}

	// tmp.VirusInfo = scanTask.ScanReport.Virus.Virus

	virusScan.postgresSvc.InsertVirusInfo(ctx, scanImage, tableID)
}

func (virusScan *VirusScan) getCachedEntry(ctx context.Context, digest string, currentLayerCache map[string]*model.VirusCachedLayer) (*model.VirusCachedLayer, error) {
	iter := virusScan.redisClient.Scan(ctx, 0, "virusScan*"+digest, 0).Iterator()
	if err := iter.Err(); err != nil {
		logging.Get().Err(err).Str("layerDigest", digest).Msg("Failed to iterate over cache entries")
		if currLayer, exists := currentLayerCache[digest]; exists {
			return currLayer, nil
		}
		return nil, fmt.Errorf("Layer exists neither in global, nor local cache")
	}
	if iter.Next(ctx) {
		v := iter.Val()
		cacheEntry, err := virusScan.redisClient.Get(ctx, v).Result()
		if err == redis.Nil {
			// Such situation could happen, if in the meantime the cache cleaning process has removed
			// this entry (because the clair database has updated for tree containing this layer).
			// In such case return the local cache result.
			logging.Get().Info().Str("layerDigest", digest).Msg("Cached entry cleared during scanning the image. Taking the local cache entry")
			if currLayer, exists := currentLayerCache[digest]; exists {
				return currLayer, nil
			}
			return nil, fmt.Errorf("Layer exists neither in global, nor local cache")
		} else if err != nil {
			logging.Get().Err(err).Str("layerDigest", digest).Msg("Error getting layer from cache")
			if currLayer, exists := currentLayerCache[digest]; exists {
				return currLayer, nil
			}
			return nil, fmt.Errorf("Layer exists neither in global, nor local cache")
		} else {
			cachedLayer := &model.VirusCachedLayer{
				Digest: digest,
			}
			err = json.Unmarshal([]byte(cacheEntry), cachedLayer)
			if err != nil {
				logging.Get().Info().Str("layerDigest", digest).Msg("Couldn't unmarshal layer entry from cache")
				if currLayer, exists := currentLayerCache[digest]; exists {
					return currLayer, nil
				}
				return nil, fmt.Errorf("Layer exists neither in global, nor local cache")
			}
			return cachedLayer, nil
		}
	} else {
		logging.Get().Info().Str("layerDigest", digest).Msg("Cached entry cleared during scanning the image. Taking the local cache entry")
		if currLayer, exists := currentLayerCache[digest]; exists {
			return currLayer, nil
		}
		return nil, fmt.Errorf("Layer exists neither in global, nor local cache")
	}
}

func (virusScan *VirusScan) logAndUpdateMongoStatus(ctx context.Context, scanTask model.VirusScanTask, status string, message string, originalErr error, flag bool) {
	mongoCtx, mongoCtxCancel := context.WithTimeout(ctx, mongoTimeout)
	defer mongoCtxCancel()

	if originalErr != nil {
		logging.Get().Err(originalErr).Msg(message)
		scanTask.Message = fmt.Sprintf("%s: %s", message, originalErr)
	}

	scanTask.FinishedAt = time.Now().Unix()
	scanTask.HistoricisedTimestamp = time.Now()
	scanTask.Status = status

	filter := bson.M{"_id": scanTask.ID}
	update := bson.M{"$set": scanTask}
	_, err := virusScan.mongodb.Collection(model.VirusScanTaskCollection.String()).UpdateOne(mongoCtx, filter, update)
	if err != nil {
		logging.Get().Error().
			Err(err).
			Str("scanTask", fmt.Sprintf("%+v", scanTask)).
			Msg("error in updating task in Mongo")
		// return err
	}

	/*	if flag == true {
			util.ImageQuestion(virusScan.postgresSvc.postgresDB, scanTask.ID.Hex(), model.QUESTION_VIRUS, true, scanTask.ImageDigest)
		} else {
			util.ImageQuestion(virusScan.postgresSvc.postgresDB, scanTask.ID.Hex(), model.QUESTION_VIRUS, false, scanTask.ImageDigest)
		}*/

	/*if scanTask.Status == model.ScanStatusSucceeded || scanTask.Status == model.ScanStatusFailed || scanTask.Status == model.ScanStatusUnprocessableEntity {
		err := util.ScanFinish(virusScan.postgresSvc.postgresDB, scanTask.ImageDigest)
		if err != nil {
			logging.GetLogger().Error().Msgf("update  image  scan finish time error：%+v", err)
		}
	}*/
}

func (virusScan *VirusScan) virusProcessLayer(ctx context.Context, hub *registry.Registry, scanTask model.VirusScanTask, currentlyCachedLayers *map[string]*model.VirusCachedLayer, digest string, client *layerManage.LocalLayerManageClient) error {
	currLayer := (*currentlyCachedLayers)[digest]
	virusInfos, webshellInfo, err := virusScan.ScanLayer(ctx, hub, digest, scanTask.Repository, client, scanTask)
	virusScan.generateVirusScanResult(virusInfos, webshellInfo, currLayer)
	if err != nil {
		logging.Get().Err(err).Msg("error in Virus ScanLayer")
		//return err
	}
	err = virusScan.updateCacheEntry(ctx, currentlyCachedLayers, digest)
	if err != nil {
		logging.Get().Info().Str("layerDigest", currLayer.Digest).Msg("Couldn't update cache entry")
	}
	return nil
}

func (virusScan *VirusScan) updateCacheEntry(ctx context.Context, currentLayerCache *map[string]*model.VirusCachedLayer, layer string) error {
	if _, exists := (*currentLayerCache)[layer]; !exists {
		return fmt.Errorf("Layer exists neither in global, nor local cache")
	}
	_, err := virusScan.redisClient.Get(ctx, "virusScan"+"_"+layer).Result()
	if err != nil {
		logging.Get().Err(err).Str("layerDigest", layer).Msg("Error getting layer from cache. Not persisting")
		return nil
	}

	if err == redis.Nil {
		logging.Get().Info().Str("layerDigest", layer).Msg("Persisting in cache")
		cacheEntry, err := json.Marshal((*currentLayerCache)[layer])
		if err != nil {
			logging.Get().Err(err).Str("layerDigest", layer).Msg("Layer could not be marshaled. Not persisting")
			return nil
		}
		redisCtx, redisCtxCancel := context.WithTimeout(ctx, redisTimeout)
		defer redisCtxCancel()
		_, err = virusScan.redisClient.Set(redisCtx, "virusScan"+"_"+layer, cacheEntry, redisTTL).Result()
		if err != nil {
			logging.Get().Err(err).Str("layerDigest", layer).Msg("Layer could not be cached. Not persisting")
			return nil
		}
		logging.Get().Info().Str("layerDigest", layer).Msg("Layer successfully cached")
		return nil
	}

	logging.Get().Info().Str("layerDigest", layer).Msg("Another worker recently scanned this layer. No need to persist")
	return nil
}

func (virusScan *VirusScan) generateVirusScanResult(virusInfos []model.VirusInfo, webshellInfos []model.WebShellInfo, currLayer *model.VirusCachedLayer) {
	currLayer.ScanReport = &model.VirusCachedScanWorkerReport{
		Virus:     virusInfos,
		Webshells: webshellInfos,
	}
}

type fileContent struct {
	fileName string
	reader   io.Reader
}

func (virusScan *VirusScan) ScanLayer(ctx context.Context, hub *registry.Registry, digest string, repository string, client *layerManage.LocalLayerManageClient, scanTask model.VirusScanTask) ([]model.VirusInfo, []model.WebShellInfo, error) {
	// d := dig.NewDigestFromHex(strings.Split(digest, ":")[0], strings.Split(digest, ":")[1])
	digestNum := strings.Split(digest, ":")[1]
	timeUnix := time.Now().Unix()
	timeUnixStr := strconv.FormatInt(timeUnix, 10)

	layerPath, err := virusScan.GetLayerPath(ctx, client, scanTask, digest)
	defer virusScan.DeleteLayerPath(ctx, client, digest)
	if err != nil {
		return []model.VirusInfo{}, []model.WebShellInfo{}, fmt.Errorf("Get local layer manage client err %v", err)
	}
	err = os.Mkdir("/tmpscan/"+digestNum+timeUnixStr+"/", 0777)
	if err != nil {
		return []model.VirusInfo{}, []model.WebShellInfo{}, fmt.Errorf("ScanLayer make Tmp Dir err %v", err)
	}
	defer os.RemoveAll("/tmpscan/" + digestNum + timeUnixStr + "/")
	sendCh := make(chan *fileContent, 10)
	revcCh := virusScan.webShellTask(ctx, sendCh, 0)

	fileCount, err := virusScan.parseLayerTar(layerPath, "/tmpscan/"+digestNum+timeUnixStr+"/", sendCh)
	if err != nil {
		return []model.VirusInfo{}, []model.WebShellInfo{}, fmt.Errorf("Failed to parseLayerTar: %w", err)
	}

	// weshell检测结果
	webshellResult := <-revcCh

	if fileCount == 0 {
		return []model.VirusInfo{}, webshellResult, nil
	}
	virusInfos, err := virusScan.clamavScan(ctx, "/tmpscan/"+digestNum+timeUnixStr+"/", digestNum)
	if err != nil {
		return []model.VirusInfo{}, webshellResult, fmt.Errorf("Clamscan Error %w", err)
	}
	// os.Remove("/tmpscan/" + digest + "layer.tar")
	if len(virusInfos) != 0 {
		logging.Get().Info().Str("Filename:", virusInfos[0].FileName).Str("Virusname:", virusInfos[0].VirusName).Str("FilePath", virusInfos[0].FilePath).Msg("The digest scan result")
	}
	return virusInfos, webshellResult, nil
}

func (virusScan *VirusScan) getCachedGraph(ctx context.Context, layers []string, scanTask model.VirusScanTask) (map[string]*model.VirusCachedLayer, []string, error) {
	currentLayerCache := make(map[string]*model.VirusCachedLayer)
	toScan := make([]string, 0)
	var prevLayer string
	for i, layer := range layers {
		cachedLayer := &model.VirusCachedLayer{
			Digest: layer,
		}
		iter := virusScan.redisClient.Scan(ctx, 0, "*virusScan_"+layer, 0).Iterator()
		if err := iter.Err(); err != nil {
			logging.Get().Err(err).Msg("Failed to get cache entry")
			currentLayerCache[layer] = cachedLayer
			toScan = append(toScan, layer)
		} else {
			if iter.Next(ctx) {
				v := iter.Val()
				cacheEntry, err := virusScan.redisClient.Get(ctx, v).Result()
				if err == redis.Nil {
					logging.Get().Info().Str("layerDigest", layer).Msg("Layer not cached. Need to scan")
					toScan = append(toScan, layer)
				} else if err != nil {
					logging.Get().Err(err).Str("layerDigest", layer).Msg("Error getting layer from cache")
					toScan = append(toScan, layer)
				} else {
					err = json.Unmarshal([]byte(cacheEntry), cachedLayer)
					if err != nil {
						logging.Get().Err(err).Str("layerDigest", layer).Msg("Layer could not be unmarshaled.")
						toScan = append(toScan, layer)
					} else {
						logging.Get().Info().Str("layerDigest", layer).Msg("Layer cached. No need to scan")
					}
				}
				currentLayerCache[layer] = cachedLayer
				if i != 0 {
					currentLayerCache[layer].Parent = prevLayer
				} else {
					currentLayerCache[layer].ImageDigests = util.AppendIfMissing(cachedLayer.ImageDigests, layer)
					currentLayerCache[layer].Repositories = util.AppendIfMissing(cachedLayer.Repositories, scanTask.Repository)
					currentLayerCache[layer].Tags = util.AppendIfMissing(cachedLayer.Tags, scanTask.Tag)
				}
			} else {
				logging.Get().Info().Str("layerDigest", layer).Msg("Layer not cached. Need to scan")
				toScan = append(toScan, layer)
				currentLayerCache[layer] = cachedLayer
				if i != 0 {
					currentLayerCache[layer].Parent = prevLayer
				}
			}
		}
		prevLayer = layer
	}
	return currentLayerCache, toScan, nil
}

func (virusScan *VirusScan) readManifest(ctx context.Context, version string, hub *registry.Registry, scanTask model.VirusScanTask) ([]string, error) {
	layers := make([]string, 0)
	uniqueLayers := make(map[string]bool)
	if version == "v1" {
		manifest, err := hub.Manifest(scanTask.Repository, scanTask.Tag)
		if err != nil {
			return []string{}, fmt.Errorf("Could not read docker V1 manifest: %w", err)
		}
		for _, layer := range manifest.Manifest.FSLayers {
			layerDigest := layer.BlobSum.String()
			if _, ok := uniqueLayers[layerDigest]; ok {
				return []string{}, fmt.Errorf("Found duplicate layer digest in V1 manifest")
			}
			uniqueLayers[layerDigest] = true
			layers = append([]string{layerDigest}, layers...)
		}
	} else if version == "v2" {
		manifest, err := hub.ManifestV2(scanTask.Repository, scanTask.Tag)
		if err != nil {
			return []string{}, fmt.Errorf("Could not read docker V2 manifest: %w", err)
		}
		for _, layer := range manifest.Manifest.Layers {
			layerDigest := layer.Digest.String()
			if _, ok := uniqueLayers[layerDigest]; ok {
				// return []string{}, fmt.Errorf("Found duplicate layer digest in V2 manifest")
				continue
			}
			uniqueLayers[layerDigest] = true
			layers = append(layers, layerDigest)
		}
	}
	return layers, nil
}

func (virusScan *VirusScan) decodeUsernamePassword(scanTask model.VirusScanTask) (string, string, error) {
	// scanTask.Authorization == Basic cm9ib3QkdHMt...

	headerSplit := strings.Split(scanTask.Authorization, " ")
	if len(headerSplit) != 2 {
		return "", "", fmt.Errorf("Expected 'Basic ASDF' format, but got different")
	}
	b64Encoded := headerSplit[1]

	decodedHeader, err := base64.StdEncoding.DecodeString(b64Encoded)
	if err != nil {
		return "", "", fmt.Errorf("Couldn't decode auth string: %w", err)
	}

	// decodedHeader == robot$ts-cdffae66-0edd-11eb-91a9-4e1d0aed31d4:eyJhbGciOiJSUzI1...

	usernamePasswordArr := strings.Split(string(decodedHeader), ":")
	if len(usernamePasswordArr) != 2 {
		return "", "", fmt.Errorf("Expected 'username:password' format, but got different")
	}

	username := usernamePasswordArr[0]
	password := usernamePasswordArr[1]

	return username, password, nil
}

func (virusScan *VirusScan) GetAllScanStatus() (int, int) {
	// res := []model.VirusScanStatusInfo{}
	waitNum := 0
	doingNum := 0
	virusScan.statusQueue.Range(func(k, v interface{}) bool {
		if v.(model.VirusScanQueueInfo).Status == "wait" {
			waitNum++
		}
		if v.(model.VirusScanQueueInfo).Status == "doing" {
			doingNum++
		}
		// res = append(res, model.VirusScanStatusInfo{Digest: k.(string), Status: v.(model.VirusScanQueueInfo).Status})
		return true
	})
	return waitNum, doingNum
}

func (virusScan *VirusScan) GetSha256ScanStatus(sha string) string {
	res, ok := virusScan.statusQueue.Load(sha)
	if !ok {
		return ""
	}
	return res.(model.VirusScanQueueInfo).Status
}

func (virusScan *VirusScan) GetLayerPath(ctx context.Context, client *layerManage.LocalLayerManageClient, scanTask model.VirusScanTask, digest string) (string, error) {
	/*client, err := layerManage.NewLocalLayerManageClient(llms)
	if err != nil {
		return "", fmt.Errorf("new local layer manage client err %v", err)
	}*/
	logging.Get().Info().Str("Digest:", digest).Msg("VirusScan Get Layer")
	username, password, err := virusScan.decodeUsernamePassword(scanTask)
	if err != nil {
		return "", fmt.Errorf("decodeUsernamePassword err %v", err)
	}
	layerURL, _, err := client.GetLayer(ctx, username, password, scanTask.URL, scanTask.Repository, digest, true)
	if err != nil {
		return "", fmt.Errorf("get layer err %v", err)
	}
	return layerURL, nil
}
func (virusScan *VirusScan) DeleteLayerPath(ctx context.Context, client *layerManage.LocalLayerManageClient, digest string) {
	logging.Get().Info().Str("Digest:", digest).Msg("VirusScan Delete Layer")
	err := client.DeleteLayer(ctx, digest)
	if err != nil {
		logging.Get().Err(err).Msg("virusScan DeleteLayerPath error")
	}
}

// call webshell server
func (virusScan *VirusScan) webShellTask(ctx context.Context, ch <-chan *fileContent, taskNum int32) <-chan []model.WebShellInfo {
	// The default value of taskNum is 6
	if taskNum <= 0 {
		taskNum = 6
	}

	var resultChan = make(chan model.WebShellInfo)
	var resultChan1 = make(chan []model.WebShellInfo)

	for i, end := int32(0), taskNum; i < end; i++ {

		// run task
		go func() {
			defer func() {
				// The last completed task closes the channel resultChan
				if atomic.AddInt32(&taskNum, -1) == 0 {
					close(resultChan)
				}
			}()

			for {
				file, ok := <-ch
				if !ok {
					break
				}

				webshellInfo, err := virusScan.webShellCall(ctx, file.reader)
				if err != nil || webshellInfo == nil || webshellInfo.Score < 4 {
					continue
				}

				webshellInfo.FilePath, webshellInfo.FileName = filepath.Split(file.fileName)

				resultChan <- *webshellInfo
			}

		}()
	}

	// result collector
	go func() {
		defer func() { close(resultChan1) }()

		r := make([]model.WebShellInfo, 0)
		for webshellResult := range resultChan {
			r = append(r, webshellResult)
		}

		// send all results
		resultChan1 <- r
	}()

	return resultChan1
}

func (virusScan *VirusScan) webShellCall(ctx context.Context, reader io.Reader) (*model.WebShellInfo, error) {

	defer func() {
		if err := recover(); err != nil {
			logging.Get().Error().Msgf("call webshell server failed, panic: %v stack: %s", err, string(debug.Stack()))
		}
	}()

	req, err := http.NewRequest(http.MethodPost, virusScan.webshellAddr, reader)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	req.Close = true

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		_, _ = io.Copy(ioutil.Discard, res.Body)
		return nil, fmt.Errorf("error http code: %d", res.StatusCode)
	}
	var s = &model.WebShellInfo{}
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(s)
	if err != nil {
		return nil, err
	}

	return s, nil
}

// 判断webshell文件后缀是否是给定的后缀
func webshellFileExt(ext string) bool {

	for i := range extSlice {
		if extSlice[i] == ext {
			return true
		}
	}

	return false
}

func (virusScan *VirusScan) updateRiskVirusCacheEntry(ctx context.Context, scantask model.VirusScanTask) {
	url := strings.Replace(scantask.URL, "https://", "", 1)
	url = strings.Replace(url, "http://", "", 1)
	image := "riskexp-image-virus-" + url + "/" + scantask.Repository + ":" + scantask.Tag
	sumData := model.ImageVirusSumData{}
	sumData.CriticalNum = int64(len(scantask.ScanReport.Virus.Virus))
	bytes, err := json.Marshal(sumData)
	if err != nil {
		logging.Get().Err(err).Msgf("Risk Virus json Marshal error")
		return
	}
	err = virusScan.redisClientShare.Set(ctx, image, bytes, riskTTL).Err()
	if err != nil {
		logging.Get().Err(err).Msgf("Updata risk cache error image:%v", image)
	}
}

func calculateWebshellScore(webshell model.WebShellInfo, flag *int) float64 {
	if (webshell.Score >= 4 && webshell.Score <= 5) && !((*flag & 2) == 2) {
		*flag += 2
		return webshellFourToFive
	} else if (webshell.Score >= 6 && webshell.Score <= 8) && !((*flag & 4) == 4) {
		*flag += 4
		return webshellSixToEight
	} else if (webshell.Score >= 9 && webshell.Score <= 10) && !((*flag & 8) == 8) {
		*flag += 8
		return webshellNineToTen
	} else {
		return 0
	}
}
