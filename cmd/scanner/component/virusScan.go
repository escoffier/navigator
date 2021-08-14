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
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	dockerarchive "github.com/docker/docker/pkg/archive"
	"github.com/go-redis/redis/v8"
	"github.com/heroku/docker-registry-client/registry"
	"github.com/rs/zerolog"
	layerManage "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/layer_manage"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	. "gitlab.com/piccolo_su/vegeta/pkg/apperror"
	"gitlab.com/piccolo_su/vegeta/pkg/flag"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type VirusScan struct {
	ctx           context.Context
	mongodb       *mongo.Database
	postgresSvc   *store.ScannerDB
	redisClient   *redis.Client
	scanTasksChan chan model.VirusScanTask
	cicdTasksChan chan model.VirusScanTask
	numWorkers    int
	statusQueue   sync.Map
}

const (
	virusScanOneTimeout = time.Minute * 15
	virusSingleScore    = 40
)

func NewViursScanService(ctx context.Context, clairOpts *flag.ClairOpts, db *mongo.Database, postgresSvc *store.ScannerDB, rc *redis.Client, updateOpts *flag.UpdateOpts) (*VirusScan, error) {
	return &VirusScan{
		ctx:           ctx,
		mongodb:       db,
		postgresSvc:   postgresSvc,
		redisClient:   rc,
		scanTasksChan: make(chan model.VirusScanTask, 1000),
		cicdTasksChan: make(chan model.VirusScanTask, 10),
		numWorkers:    clairOpts.NumWorkers,
		statusQueue:   sync.Map{},
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
		return NewMongoError(http.StatusInternalServerError, fmt.Errorf("Orphan collection - cursor error: %w", err))
	}

	logging.GetLogger().Info().
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
		logging.GetLogger().Error().Msgf("virusScan failDanglingTasks error %v", err)
	}

	var wg sync.WaitGroup
	err = os.Mkdir("/tmpscan", 0777)
	if err != nil {
		logging.GetLogger().Error().Msgf("virusScan Mkdir error %v", err)
		return err
	}
	for i := 0; i < virusScan.numWorkers; i++ {
		wg.Add(1)
		go virusScan.workerRun(ctx, i, &wg, llms)
	}
	wg.Wait()
	log.Info().Msg("All VirusScan workers finished")
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
			zerolog.Ctx(ctx).Info().Err(err).Str("Out:", out.String()).Str("Stderr:", stderr.String()).Str("ScanPath:", scanPath).Msg("Cla ERROR")
			return []model.VirusInfo{}, fmt.Errorf("ClamScan Error %w", err)
		}
		// os.Remove("/configs/" + digestMy + "layer.tar")
		// return []model.ClamAvVirus{}
	}

	zerolog.Ctx(ctx).Info().Msg("Clamscan ok")
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
func (virusScan *VirusScan) parseLayerTar(tarFileName string, dst string) (uint64, error) {
	tarFile, err := os.Open(tarFileName)
	if err != nil {
		return 0, fmt.Errorf("Failed to advance tarReader: %w", err)
	}
	decompressStreamReader, err := dockerarchive.DecompressStream(tarFile)
	if err != nil {
		return 0, fmt.Errorf("Failed to DecompressStream: %w", err)
	}
	tarReader := tar.NewReader(decompressStreamReader)
	var count uint64 = 0
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return count, fmt.Errorf("Failed to advance tarReader: %w", err)
		}
		test := header.FileInfo()
		if header.Typeflag == tar.TypeDir {
			continue
		} else if (header.Typeflag == tar.TypeLink) || (header.Typeflag == tar.TypeSymlink) { // 过滤软链接和硬链接
			continue
		} else {
			// fmt.Println(header.Name)
			perm := test.Mode().Perm()
			flag := perm & os.FileMode(73)
			if uint32(flag) == uint32(73) {
				file, _ := virusScan.createFile(dst + header.Name)
				_, err := io.Copy(file, tarReader)
				if err != nil {
					logging.GetLogger().Error().Msgf("virusScan io.Copy error %v", err)
				}
				err = os.Chmod(dst+header.Name, 0666)
				if err != nil {
					logging.GetLogger().Error().Msgf("virusScan os.Chmod error %v", err)
				}
				count++
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

	workerSublogger := log.With().Int("worker-id", id).Logger()
	ctx = workerSublogger.WithContext(ctx)

	zerolog.Ctx(ctx).Info().Msg("Started ViursScan worker")
loop:
	for {
		select {
		case scanTask := <-virusScan.cicdTasksChan:
			zerolog.Ctx(ctx).Info().Msg("Received CICD VirusScan task")
			virusScan.processScanTask(ctx, scanTask, llms)
			zerolog.Ctx(ctx).Info().Msg("Finish CICD VirusScan task")

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
			zerolog.Ctx(ctx).Info().Msg("Received VirusScan task")
			virusScan.processScanTask(ctx, scanTask, llms)
			zerolog.Ctx(ctx).Info().Msg("Finish VirusScan task")
		case <-ctx.Done():
			break loop
		}
	}
	zerolog.Ctx(ctx).Info().Msg("Shutting down VirusScan worker")
}

func (virusScan *VirusScan) processScanTask(ctx context.Context, scanTask model.VirusScanTask, llms *layerManage.LocalLayerManageSrv) {
	scanCtx, scanCtxCancel := context.WithTimeout(ctx, virusScanOneTimeout)
	defer scanCtxCancel()
	defer virusScan.statusQueue.Delete(scanTask.ImageDigest) // 删除状态缓存
	zerolog.Ctx(ctx).Info().
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
			zerolog.Ctx(ctx).Warn().Err(err).Msg("Certificate validation failed, but insecure option is on - will retry and skip TLS cert verification")
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
		zerolog.Ctx(ctx).Err(err).Msg("LLMS CLIENT NEW FAULT")
		virusScan.logAndUpdateMongoStatus(ctx, scanTask, model.ScanStatusFailed, "Couldn't get LLMS Client", err, false)
		return
	}
	for i := range toScan {
		err := virusScan.virusProcessLayer(scanCtx, hub, scanTask, &currentlyCachedLayers, toScan[i], client)
		if err != nil {
			logging.GetLogger().Error().Msgf("VirusScan get ToScan error :%v", err)
		}
	}
	zerolog.Ctx(ctx).Info().Msg("Virus scan finished, processed all layers")

	report := &model.VirusScanReport{}
	virus := make([]model.VirusInfo, 0)
	perLayerReport := make([]model.VirusLayerReport, 0)

	for layerNo, digest := range layers {
		cachedLayer, err := virusScan.getCachedEntry(scanCtx, digest, currentlyCachedLayers)
		if err != nil {
			cachedLayer = currentlyCachedLayers[digest]
		}
		perLayerReport = append(perLayerReport, model.VirusLayerReport{
			LayerNo:     layerNo,
			LayerDigest: digest,
			ViursInfo:   cachedLayer.ScanReport.Virus,
		})
		virus = append(virus, cachedLayer.ScanReport.Virus...)
	}
	report.Virus = model.VirusReport{
		Repository:     scanTask.Repository,
		Tag:            scanTask.Tag,
		Digest:         scanTask.ImageDigest,
		Virus:          virus,
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
		zerolog.Ctx(ctx).Err(err).Msg("Update Mongo Dockument Failed")
		return
	}*/
	zerolog.Ctx(ctx).Info().Msg("Processing of VirusScan task finished")
}

func (virusScan *VirusScan) logToLayer(ctx context.Context, scanTask model.VirusScanTask, ImageID int64) {
	for _, v := range scanTask.ScanReport.Virus.PerLayerReport {
		if len(v.ViursInfo) <= 0 {
			continue
		} else {
			res := []model.Malicious{}
			tmpScanLayer := model.ScanLayer{}
			tmpScanLayer.LayerDigest = v.LayerDigest
			tmpScanLayer.ImageId = ImageID
			for _, virus := range v.ViursInfo {
				tmpMalicious := model.Malicious{}
				tmpMalicious.VirusInfo = virus
				res = append(res, tmpMalicious)
			}
			jsondata, _ := json.Marshal(res)
			tmpScanLayer.MaliciousInfoJSON = jsondata
			virusScan.postgresSvc.InsertVirusLayer(ctx, tmpScanLayer)
		}
	}
}

func (virusScan *VirusScan) logPostgres(ctx context.Context, scanTask model.VirusScanTask, tableID int64) {
	scanImage := model.ScanImage{}
	if len(scanTask.ScanReport.Virus.Virus) > 0 {
		res := []model.Malicious{}
		scanImage.VirusScore = virusSingleScore
		for _, v := range scanTask.ScanReport.Virus.Virus {
			tmp := model.Malicious{}
			tmp.VirusInfo = v
			res = append(res, tmp)
		}
		// tmp.VirusInfo = scanTask.ScanReport.Virus.Virus
		jsondata, _ := json.Marshal(res)
		scanImage.MaliciousInfoJSON = jsondata
	} else {
		return
	}
	virusScan.postgresSvc.InsertVirusInfo(ctx, scanImage, tableID)
}

func (virusScan *VirusScan) getCachedEntry(ctx context.Context, digest string, currentLayerCache map[string]*model.VirusCachedLayer) (*model.VirusCachedLayer, error) {
	iter := virusScan.redisClient.Scan(ctx, 0, "virusScan*"+digest, 0).Iterator()
	if err := iter.Err(); err != nil {
		zerolog.Ctx(ctx).Err(err).Str("layerDigest", digest).Msg("Failed to iterate over cache entries")
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
			zerolog.Ctx(ctx).Info().Str("layerDigest", digest).Msg("Cached entry cleared during scanning the image. Taking the local cache entry")
			if currLayer, exists := currentLayerCache[digest]; exists {
				return currLayer, nil
			}
			return nil, fmt.Errorf("Layer exists neither in global, nor local cache")
		} else if err != nil {
			zerolog.Ctx(ctx).Err(err).Str("layerDigest", digest).Msg("Error getting layer from cache")
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
				zerolog.Ctx(ctx).Info().Str("layerDigest", digest).Msg("Couldn't unmarshal layer entry from cache")
				if currLayer, exists := currentLayerCache[digest]; exists {
					return currLayer, nil
				}
				return nil, fmt.Errorf("Layer exists neither in global, nor local cache")
			}
			return cachedLayer, nil
		}
	} else {
		zerolog.Ctx(ctx).Info().Str("layerDigest", digest).Msg("Cached entry cleared during scanning the image. Taking the local cache entry")
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
		zerolog.Ctx(ctx).Error().Err(originalErr).Msg(message)
		scanTask.Message = fmt.Sprintf("%s: %s", message, originalErr)
	}

	scanTask.FinishedAt = time.Now().Unix()
	scanTask.HistoricisedTimestamp = time.Now()
	scanTask.Status = status

	filter := bson.M{"_id": scanTask.ID}
	update := bson.M{"$set": scanTask}
	_, err := virusScan.mongodb.Collection(model.VirusScanTaskCollection.String()).UpdateOne(mongoCtx, filter, update)
	if err != nil {
		zerolog.Ctx(ctx).Error().
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
	virusInfos, err := virusScan.ScanLayer(ctx, hub, digest, scanTask.Repository, client, scanTask)
	virusScan.generateVirusScanResult(virusInfos, currLayer)
	if err != nil {
		zerolog.Ctx(ctx).Error().Err(err).Msg("error in Virus ScanLayer")
		return err
	}
	err = virusScan.updateCacheEntry(ctx, currentlyCachedLayers, digest)
	if err != nil {
		zerolog.Ctx(ctx).Info().Str("layerDigest", currLayer.Digest).Msg("Couldn't update cache entry")
	}
	return nil
}

func (virusScan *VirusScan) updateCacheEntry(ctx context.Context, currentLayerCache *map[string]*model.VirusCachedLayer, layer string) error {
	if _, exists := (*currentLayerCache)[layer]; !exists {
		return fmt.Errorf("Layer exists neither in global, nor local cache")
	}
	_, err := virusScan.redisClient.Get(ctx, "virusScan"+"_"+layer).Result()
	if err == redis.Nil {
		zerolog.Ctx(ctx).Info().Str("layerDigest", layer).Msg("Persisting in cache")
		cacheEntry, err := json.Marshal((*currentLayerCache)[layer])
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Str("layerDigest", layer).Msg("Layer could not be marshaled. Not persisting")
			return nil
		} else {
			redisCtx, redisCtxCancel := context.WithTimeout(ctx, redisTimeout)
			defer redisCtxCancel()
			_, err := virusScan.redisClient.Set(redisCtx, "virusScan"+"_"+layer, cacheEntry, redisTTL).Result()
			if err != nil {
				zerolog.Ctx(ctx).Error().Err(err).Str("layerDigest", layer).Msg("Layer could not be cached. Not persisting")
				return nil
			}
			zerolog.Ctx(ctx).Info().Str("layerDigest", layer).Msg("Layer successfully cached")
			return nil
		}
	} else if err != nil {
		zerolog.Ctx(ctx).Err(err).Str("layerDigest", layer).Msg("Error getting layer from cache. Not persisting")
		return nil
	}

	zerolog.Ctx(ctx).Info().Str("layerDigest", layer).Msg("Another worker recently scanned this layer. No need to persist")
	return nil
}

func (virusScan *VirusScan) generateVirusScanResult(virusInfos []model.VirusInfo, currLayer *model.VirusCachedLayer) {
	currLayer.ScanReport = &model.VirusCachedScanWorkerReport{
		Virus: virusInfos,
	}
}

func (virusScan *VirusScan) ScanLayer(ctx context.Context, hub *registry.Registry, digest string, repository string, client *layerManage.LocalLayerManageClient, scanTask model.VirusScanTask) ([]model.VirusInfo, error) {
	// d := dig.NewDigestFromHex(strings.Split(digest, ":")[0], strings.Split(digest, ":")[1])
	digestNum := strings.Split(digest, ":")[1]
	timeUnix := time.Now().Unix()
	timeUnixStr := strconv.FormatInt(timeUnix, 10)

	layerPath, err := virusScan.GetLayerPath(ctx, client, scanTask, digest)
	defer virusScan.DeleteLayerPath(ctx, client, digest)
	if err != nil {
		return []model.VirusInfo{}, fmt.Errorf("Get local layer manage client err %v", err)
	}
	err = os.Mkdir("/tmpscan/"+digestNum+timeUnixStr+"/", 0777)
	if err != nil {
		return []model.VirusInfo{}, fmt.Errorf("ScanLayer make Tmp Dir err %v", err)
	}
	defer os.RemoveAll("/tmpscan/" + digestNum + timeUnixStr + "/")
	fileCount, err := virusScan.parseLayerTar(layerPath, "/tmpscan/"+digestNum+timeUnixStr+"/")
	if err != nil {
		return []model.VirusInfo{}, fmt.Errorf("Failed to parseLayerTar: %w", err)
	}
	if fileCount == 0 {
		return []model.VirusInfo{}, nil
	}
	virusInfos, err := virusScan.clamavScan(ctx, "/tmpscan/"+digestNum+timeUnixStr+"/", digestNum)
	if err != nil {
		return []model.VirusInfo{}, fmt.Errorf("Clamscan Error %w", err)
	}
	// os.Remove("/tmpscan/" + digest + "layer.tar")
	if len(virusInfos) != 0 {
		zerolog.Ctx(ctx).Info().Str("Filename:", virusInfos[0].FileName).Str("Virusname:", virusInfos[0].VirusName).Str("FilePath", virusInfos[0].FilePath).Msg("The digest scan result")
	}
	return virusInfos, nil
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
			zerolog.Ctx(ctx).Err(err).Msg("Failed to get cache entry")
			currentLayerCache[layer] = cachedLayer
			toScan = append(toScan, layer)
		} else {
			if iter.Next(ctx) {
				v := iter.Val()
				cacheEntry, err := virusScan.redisClient.Get(ctx, v).Result()
				if err == redis.Nil {
					zerolog.Ctx(ctx).Info().Str("layerDigest", layer).Msg("Layer not cached. Need to scan")
					toScan = append(toScan, layer)
				} else if err != nil {
					zerolog.Ctx(ctx).Err(err).Str("layerDigest", layer).Msg("Error getting layer from cache")
					toScan = append(toScan, layer)
				} else {
					err = json.Unmarshal([]byte(cacheEntry), cachedLayer)
					if err != nil {
						zerolog.Ctx(ctx).Err(err).Str("layerDigest", layer).Msg("Layer could not be unmarshaled.")
						toScan = append(toScan, layer)
					} else {
						zerolog.Ctx(ctx).Info().Str("layerDigest", layer).Msg("Layer cached. No need to scan")
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
				zerolog.Ctx(ctx).Info().Str("layerDigest", layer).Msg("Layer not cached. Need to scan")
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
			waitNum += 1
		}
		if v.(model.VirusScanQueueInfo).Status == "doing" {
			doingNum += 1
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
	zerolog.Ctx(ctx).Info().Str("Digest:", digest).Msg("VirusScan Get Layer")
	username, password, err := virusScan.decodeUsernamePassword(scanTask)
	if err != nil {
		return "", fmt.Errorf("decodeUsernamePassword err %v", err)
	}
	layerUrl, _, err := client.GetLayer(username, password, scanTask.URL, scanTask.Repository, digest, true)
	if err != nil {
		return "", fmt.Errorf("get layer err %v", err)
	}
	return layerUrl, nil
}
func (virusScan *VirusScan) DeleteLayerPath(ctx context.Context, client *layerManage.LocalLayerManageClient, digest string) {
	zerolog.Ctx(ctx).Info().Str("Digest:", digest).Msg("VirusScan Delete Layer")
	err := client.DeleteLayer(digest)
	if err != nil {
		logging.GetLogger().Error().Msgf("virusScan DeleteLayerPath error %v", err)
	}
}

func (virusScan *VirusScan) updateRiskVirusCacheEntry(ctx context.Context, scantask model.VirusScanTask) {
	url := strings.Replace(scantask.URL, "https://", "", 1)
	url = strings.Replace(url, "http://", "", 1)
	image := "riskexp-image-virus-" + url + "/" + scantask.Repository + ":" + scantask.Tag
	sumData := model.ImageVirusSumData{}
	sumData.CriticalNum = int64(len(scantask.ScanReport.Virus.Virus))
	bytes, err := json.Marshal(sumData)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msgf("Risk Virus json Marshal error")
		return
	}
	err = virusScan.redisClient.Set(ctx, image, bytes, riskTTL).Err()
	if err != nil {
		logging.GetLogger().Error().Err(err).Msgf("Updata risk cache error image:%v", image)
	}
}
