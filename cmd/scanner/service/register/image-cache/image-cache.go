package image_cache

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

const (
	serviceName = "image-cache-service"
)

const (
	httpRequestPath   = "/layer"
	innerRegistryIp   = "localhost"
	innerRegistryPort = 5566
	maxWorkerNum      = 5
)

//layer file status
const (
	LayerNotPull = iota
	LayerPulled
	LayerPulling
	LayerPullErr
)

type LayerInfo struct {
	digest     string   //layer digest
	repository string   //image repository
	refCount   int      //reference count,0 means can be deleted
	url        string   //registry url
	layerUrl   string   //layer url
	status     int      //layer status
	flag       chan int //notify if pull end,when worker finish,it will do flag<-1
	username   string
	password   string
	skipTls    bool
}

type RequestLayerInfo struct {
	Repository string      `json:"repository"`
	Digest     string      `json:"digest"`
	Url        string      `json:"url"` //registry url
	Username   string      `json:"username"`
	Password   string      `json:"password"`
	Tag        string      `json:"tag"`
	SkipTls    bool        `json:"skiptls"`
	ConfigFlag int         `json:"configFlag"`
	Response   chan string `json:"-"`
}

type ResponseLayerInfo struct {
	Code       int    `json:"code"`
	Msg        string `json:"msg"`
	Url        string `json:"url"`
	LayerUrl   string `json:"layer-url"`
	Digest     string `json:"digest"`
	Repository string `json:"repository"`
}

type Config struct {
	CacheServerIp   string
	CacheServerPort int
}

// ScannerImageCacheService define image cache service which will pull image from registry and cache it in local
type ScannerImageCacheService struct {
	config    Config
	ctx       context.Context
	serverIp  string
	port      int
	server    *gin.Engine
	layerList map[string]*LayerInfo //digest->layer info
	//manifestList map[string]*ManifestInfo //digest->manifest info
	taskLock sync.Mutex
	//manifestLock sync.Mutex
	manifestList chan RequestLayerInfo
	//manifestLock sync.Mutex
	//cacheCounter CacheCounter
	fs          *FileServer
	WorkerGroup *WorkerGroup
}

func (s *ScannerImageCacheService) IsLayerExist(digest string) bool {
	_, ok := s.layerList[digest]
	return ok
}

func (s *ScannerImageCacheService) IsLayerPulled(digest string) bool {
	if s.IsLayerExist(digest) && s.layerList[digest].status == LayerPulled {
		return true
	}
	return false
}

func (s *ScannerImageCacheService) IncLayerRefCount(digest string) {
	s.layerList[digest].refCount = s.layerList[digest].refCount + 1
	log.Info().Msgf("digest %s,ADD layer refcount(%d)  ", digest, s.layerList[digest].refCount)
}

func (s *ScannerImageCacheService) IsLayerNoRef(digest string) bool {
	return s.layerList[digest].refCount == 0

}

func (s *ScannerImageCacheService) DecLayerRefCount(digest string) error {
	_, ok := s.layerList[digest]
	if !ok {
		return fmt.Errorf("not find layer,digest %s", digest)
	}
	if s.layerList[digest].refCount <= 0 {
		//some err,should have been deleted
		log.Error().Msgf("digest %s,layer refcount(%d) <=0 ", digest, s.layerList[digest].refCount)
		//still return nil,deleted by caller
		return nil
	}
	s.layerList[digest].refCount = s.layerList[digest].refCount - 1
	log.Info().Msgf("DecRef refcount(%d) ", s.layerList[digest].refCount)
	return nil
}

func (s *ScannerImageCacheService) AddLayerRecord(rq *RequestLayerInfo) {
	s.layerList[rq.Digest] = &LayerInfo{
		refCount:   1,
		status:     LayerNotPull,
		url:        rq.Url,
		digest:     rq.Digest,
		repository: rq.Repository,
		username:   rq.Username,
		password:   rq.Password,
		skipTls:    rq.SkipTls,
		flag:       make(chan int),
	}
}

func (s *ScannerImageCacheService) AddManifestTask(ctx context.Context, rq *RequestLayerInfo) {
	s.manifestList <- *rq
}

func (s *ScannerImageCacheService) WaitLayerPulled(digest string) {
	for {
		s.taskLock.Lock()
		if _, ok := s.layerList[digest]; !ok {
			log.Info().Msgf("wait layer pulled,layer %s not exist", digest)
			s.taskLock.Unlock()
			break
		}
		if s.layerList[digest].status == LayerPulled || s.layerList[digest].status == LayerPullErr {
			s.taskLock.Unlock()
			break
		}
		s.taskLock.Unlock()

		time.Sleep(time.Duration(20) * time.Millisecond)
	}
}

func (s *ScannerImageCacheService) NotifyLayerPulled(digest string) error {
	return nil
	//if _,ok := s.layerList[digest];!ok {
	//	return fmt.Errorf("layer %s not exist",digest)
	//}
	//s.layerList[digest].flag <- 1
	//log.Info().Msgf("notify digest %s end",digest)
	//return nil
}

func (s *ScannerImageCacheService) ResponseCodeAndMsg(code int, msg, digest string, ctx *gin.Context) {
	rsp := ResponseLayerInfo{
		Code:   code,
		Msg:    msg,
		Digest: digest,
	}
	if code == 0 {
		ctx.JSON(http.StatusOK, rsp)
	} else {
		ctx.JSON(http.StatusBadRequest, rsp)
	}
	log.Info().Msgf("server resp %v", rsp)
}

func (s *ScannerImageCacheService) ResponseOK(digest string, ctx *gin.Context) {
	LayerHttpPath := fmt.Sprintf("http://%s:%d/%s/%s", s.fs.externalIp, s.fs.port, digest, LayerFileName)
	rsp := ResponseLayerInfo{
		Code:       0,
		Msg:        "ok",
		Url:        LayerHttpPath,
		Digest:     digest,
		Repository: s.layerList[digest].repository,
		LayerUrl:   s.layerList[digest].layerUrl,
	}
	ctx.JSON(http.StatusOK, rsp)
}

func (s *ScannerImageCacheService) ResponseErr(digest string, ctx *gin.Context) {
	rsp := ResponseLayerInfo{
		Code:     1,
		Msg:      fmt.Sprintf("get layer info err: %d", s.layerList[digest].status),
		Url:      s.layerList[digest].url,
		LayerUrl: s.layerList[digest].layerUrl,
		Digest:   digest,
	}

	ctx.JSON(http.StatusBadRequest, rsp)
}

//url : http://0.0.0.0:xxx/layer?repository=xxx&digest=xxx&url=xxx
func (s *ScannerImageCacheService) handleDelete(ctx *gin.Context) {
	//repository 	:= ctx.Query("repository")
	digest := ctx.Query("digest")
	log.Info().Msgf("get delete req,digest %s", digest)

	s.taskLock.Lock()
	if !s.IsLayerExist(digest) {
		s.taskLock.Unlock()
		s.ResponseCodeAndMsg(1, "not find layer record", digest, ctx)
		return
	}

	//dec refcount
	err := s.DecLayerRefCount(digest)
	if err != nil {
		log.Error().Msgf("delete layer file refcount err,digest %s", digest)
	}

	// delete layer from file server
	if s.IsLayerNoRef(digest) {
		delete(s.layerList, digest)
		err = s.fs.DeleteFile(digest)
		if err != nil {
			log.Error().Msgf("delete layer file err,digest %s", digest)
		}
	} else {
		log.Info().Msgf("digest %s still has ref,no delete", digest)
	}

	//delete from layerlist
	//delete(s.layerList, digest)

	s.taskLock.Unlock()

	s.ResponseCodeAndMsg(0, "dec layer ref-count ok", digest, ctx)
}

func (s *ScannerImageCacheService) handleGet(ctx *gin.Context) {
	log.Info().Msgf("local layer manage get request")
	ctx.JSON(200, gin.H{
		"message": "pong",
	})
}

func (s *ScannerImageCacheService) handleClearCache(ctx *gin.Context) {
	log.Info().Msgf("local layer manage get ClearCache request")
	ctx.JSON(200, gin.H{
		"message": "pong",
	})
}

func (s *ScannerImageCacheService) handleFindBlob(ctx *gin.Context, repository string, refer string) {
	//repository := ctx.Param("name")
	fp := filepath.Join(s.fs.rootPath, "data", refer)
	fpLayer := "FileServerCache/" + fp + "/layer.tar"
	fmt.Println(fpLayer)
	if !FileExists(fpLayer) {
		fmt.Println("file not exist ", fpLayer)
		fpManifest := "FileServerCache/" + fp + "/" + refer + ".json"
		if !FileExists(fpManifest) {
			fmt.Println("file not exist ", fpManifest)
			ctx.Status(400)
			return
		} else {
			fmt.Println(fpManifest)
			fp = fpManifest
		}
	} else {
		fp = fpLayer
	}
	ctx.File(fp)
	//ctx.File("/worker1/tensornavigator/test/cmd/scanner/component/layer_manage/" + fp)
}

func (s *ScannerImageCacheService) handleFindManifesst(ctx *gin.Context, repository string, refer string) {

	fp := filepath.Join(s.fs.rootPath, "manifests", repository, refer)
	fp = filepath.Join(fp, "manifest.json")
	fp = "FileServerCache/" + fp
	fmt.Println(fp)
	if !FileExists(fp) {
		fmt.Println("no find")
		ctx.Status(404)
		return
	}
	manifestJson, err := os.ReadFile(fp)
	if err != nil {
		fmt.Println(err)
		ctx.Status(404)
		return
	}

	ctx.String(200, string(manifestJson))
}

func (s *ScannerImageCacheService) handleManifest(ctx *gin.Context) {
	log.Info().Msgf("local layer manage get Manifest post request")
	var body []byte
	if ctx.Request.Body != nil {
		if data, err := ioutil.ReadAll(ctx.Request.Body); err == nil {
			body = data
		}
	}
	if len(body) == 0 {
		if err := ctx.AbortWithError(http.StatusBadRequest, fmt.Errorf("empty body")); err != nil {
			log.Error().Msgf("failed to abort request: %s", err.Error())
		}
		return
	}
	rq := &RequestLayerInfo{}
	err := json.Unmarshal(body, rq)
	if err != nil {
		log.Error().Msgf(" json unmarshal err %v", err)

		ctx.JSON(http.StatusBadRequest, ResponseLayerInfo{
			Code:       1,
			Msg:        err.Error(),
			Repository: rq.Repository,
			Digest:     rq.Digest,
		})
	}

	log.Info().Msgf("get request %+v", rq)
	//s.manifestLock.Lock()
	rq.Response = make(chan string, 1)
	s.AddManifestTask(ctx, rq)
	str := <-rq.Response
	if strings.Contains(str, "GetManifestError") {
		ctx.JSON(400, str)
	} else {
		ctx.String(200, "%s", str)
	}
}

//url : http://0.0.0.0:xxx/layer?
func (s *ScannerImageCacheService) handlePost(ctx *gin.Context) {
	log.Info().Msg("local layer manage get post request")

	var body []byte
	if ctx.Request.Body != nil {
		if data, err := ioutil.ReadAll(ctx.Request.Body); err == nil {
			body = data
		}
	}

	if len(body) == 0 {
		if err := ctx.AbortWithError(http.StatusBadRequest, fmt.Errorf("empty body")); err != nil {
			log.Error().Msgf("failed to abort request: %s", err.Error())
		}
		return
	}
	//log.Info().Msgf("get body %v",body)

	rq := &RequestLayerInfo{}
	err := json.Unmarshal(body, rq)
	if err != nil {
		log.Error().Msgf(" json unmarshal err %v", err)

		ctx.JSON(http.StatusBadRequest, ResponseLayerInfo{
			Code:       1,
			Msg:        err.Error(),
			Repository: rq.Repository,
			Digest:     rq.Digest,
		})
	}

	log.Info().Msgf("get request %+v", rq)

	s.taskLock.Lock()
	//check if already pulled
	if s.IsLayerExist(rq.Digest) {
		log.Info().Msgf("layer %s exist", rq.Digest)
		s.IncLayerRefCount(rq.Digest)
		s.taskLock.Unlock()
		if s.IsLayerPulled(rq.Digest) {
			//pulled, return
			s.ResponseOK(rq.Digest, ctx)
			return
		}
		//if exist but not pulled,go to WaitLayerPulled
	} else {
		log.Info().Msgf("add record ")

		//not find,add new record
		s.AddLayerRecord(rq)
		s.taskLock.Unlock()
	}

	log.Info().Msgf("wait layer pulled,refcount %d", s.layerList[rq.Digest].refCount)

	//check if layer has been pulled
	s.WaitLayerPulled(rq.Digest)

	log.Info().Msgf("layer %s check end", rq.Digest)

	if s.layerList[rq.Digest].status == LayerPulled {
		s.ResponseOK(rq.Digest, ctx)
	} else {
		s.ResponseErr(rq.Digest, ctx)
	}
}

func (s *ScannerImageCacheService) OpenGinLog() {
	//test log
	gin.DisableConsoleColor()

	// Logging to a file.
	logpath := filepath.Join(os.TempDir(), "ginlog.log")
	log.Info().Msgf("gin log path %s", logpath)
	f, _ := os.Create(logpath)
	gin.DefaultWriter = io.MultiWriter(f)
}

func (s *ScannerImageCacheService) CreateServer() {
	//test
	//s.OpenGinLog()
	server := gin.New()

	server.GET("/v2/*xx", func(ctx *gin.Context) {
		if strings.LastIndex(ctx.Request.RequestURI, "/blobs/") > 0 {
			v2Index := strings.Index(ctx.Request.RequestURI, "/v2/")
			blobIndex := strings.LastIndex(ctx.Request.RequestURI, "/blobs/")
			respository := ctx.Request.RequestURI[v2Index+4 : blobIndex]
			refer := ctx.Request.RequestURI[blobIndex+7:]
			//fmt.Printf("%v %v\n", respository, refer)
			s.handleFindBlob(ctx, respository, refer)
		}

		if strings.LastIndex(ctx.Request.RequestURI, "/manifests/") > 0 {
			v2Index := strings.Index(ctx.Request.RequestURI, "/v2/")
			manifestIndex := strings.LastIndex(ctx.Request.RequestURI, "/manifests/")
			respository := ctx.Request.RequestURI[v2Index+4 : manifestIndex]
			refer := ctx.Request.RequestURI[manifestIndex+11:]
			//fmt.Printf("%v %v\n", respository, refer)
			s.handleFindManifesst(ctx, respository, refer)
		} else {
			ctx.Status(200)
		}
	})

	server.POST("/manifest", func(ctx *gin.Context) {
		s.handleManifest(ctx)
	})
	server.POST(httpRequestPath, func(ctx *gin.Context) {
		s.handlePost(ctx)
	})
	server.DELETE(httpRequestPath, func(ctx *gin.Context) {
		s.handleDelete(ctx)
	})
	//for test
	server.GET(httpRequestPath, func(ctx *gin.Context) {
		s.handleGet(ctx)
	})
	//clearCache
	server.GET("/clearCache", func(ctx *gin.Context) {
		s.handleClearCache(ctx)
	})
	s.server = server
}

func (s *ScannerImageCacheService) StartServer() {
	go func() {
		address := fmt.Sprintf("%s:%d", s.serverIp, s.port)
		logging.GetLogger().Info().Msgf("image cache start server :%s", address)
		err := s.server.Run(address)
		if err != nil {
			log.Error().Msgf("start s server err %v", err)
		}
		log.Info().Msg("image cache server end")
	}()

	log.Info().Msgf("image cache service listen on port %d", s.port)
}

func (s *ScannerImageCacheService) FindAndModiyPullTask() (LayerInfo, error) {
	res := LayerInfo{}
	s.taskLock.Lock()
	for k, v := range s.layerList {
		if v.status == LayerNotPull {
			res.username = v.username
			res.password = v.password
			res.skipTls = v.skipTls
			res.digest = v.digest
			res.repository = v.repository
			res.url = v.url
			//set task to pulling
			s.layerList[k].status = LayerPulling
			res.status = LayerPulling
			break
		}
	}
	s.taskLock.Unlock()

	return res, nil
}

func (s *ScannerImageCacheService) UpdateTaskStatusAndLayerUrl(digest, layerUrl string, status int) error {
	if _, ok := s.layerList[digest]; !ok {
		return fmt.Errorf("not found layer %s", digest)
	}
	s.taskLock.Lock()
	s.layerList[digest].status = status
	if len(layerUrl) != 0 {
		s.layerList[digest].layerUrl = layerUrl
	}
	s.taskLock.Unlock()

	return nil
}

func (s *ScannerImageCacheService) Start(ctx context.Context) error {
	//start inner registry server
	s.CreateServer()
	logging.GetLogger().Info().Msg("image cache create server ok")

	s.StartServer()

	//start file server
	err := s.fs.Run(s.ctx)
	if err != nil {
		log.Error().Err(err).Msg("start file server failed")
		return err
	}

	//run worker
	s.WorkerGroup.Run()

	logging.GetLogger().Info().Msg("start image cache service ok")
	return nil
}

func (s *ScannerImageCacheService) Stop(ctx context.Context) error {
	//if err := s.server.Run(ctx); err != nil {
	//	logging.GetLogger().Error().Err(err).Msg("image cache server stop err")
	//	return err
	//}
	logging.GetLogger().Info().Msg("image cache server stop")
	return nil
}

func init() {
	err := register.Register(serviceName, newService)
	if err != nil {
		logging.GetLogger().Error().Err(err).Str("serviceName", serviceName).Msg("int service err")
	}
}

func newService(config register.ScannerServiceConfig) (register.ScannerService, error) {
	s := &ScannerImageCacheService{
		serverIp:     innerRegistryIp,
		port:         innerRegistryPort,
		manifestList: make(chan RequestLayerInfo, 100),
	}
	s.config.CacheServerPort = config.Options.ImageCacheServerPort
	s.config.CacheServerIp = config.Options.ImageCacheServerIp

	l := make(map[string]*LayerInfo)
	fs, _ := NewFileServer(context.Background(), FileServerRootDir, s.config.CacheServerIp, innerRegistryIp, s.config.CacheServerPort)
	s.layerList = l
	s.fs = fs

	wg, _ := NewWorkerGroup(s, maxWorkerNum)
	s.WorkerGroup = wg
	logging.GetLogger().Info().Msg("new image cache service ok")
	return s, nil
}
