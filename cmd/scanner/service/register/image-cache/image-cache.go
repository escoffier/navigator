package imagecache

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
	"time"

	"github.com/gin-gonic/gin"
	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
)

const (
	serviceName = "image-cache-service"
)

const (
	httpRequestPath   = "/layer"
	innerRegistryIP   = "localhost"
	innerRegistryPort = 5566
	maxWorkerNum      = 5
)

// layer file status
const (
	LayerNotPull = iota
	LayerPulled
	LayerPulling
	LayerPullErr
)

type LayerInfo struct {
	digest     string   // layer digest
	repository string   // image repository
	refCount   int      // reference count,0 means can be deleted
	url        string   // registry url
	layerURL   string   // layer url
	status     int      // layer status
	flag       chan int // notify if pull end,when worker finish,it will do flag<-1
	username   string
	password   string
	skipTLS    bool
}

type RequestLayerInfo struct {
	Repository string      `json:"repository"`
	Digest     string      `json:"digest"`
	URL        string      `json:"url"` // registry url
	Username   string      `json:"username"`
	Password   string      `json:"password"`
	Tag        string      `json:"tag"`
	SkipTLS    bool        `json:"skiptls"`
	ConfigFlag int         `json:"configFlag"`
	Response   chan string `json:"-"`
}

type ResponseLayerInfo struct {
	Code       int    `json:"code"`
	Msg        string `json:"msg"`
	URL        string `json:"url"`
	LayerURL   string `json:"layer-url"`
	Digest     string `json:"digest"`
	Repository string `json:"repository"`
}

type Config struct {
	CacheServerIP   string
	CacheServerPort int
}

// ScannerImageCacheService define image cache service which will pull image from registry and cache it in local
type ScannerImageCacheService struct {
	config       Config
	ctx          context.Context
	serverIP     string
	port         int
	server       *gin.Engine
	LayerQueue   *LayerQueue
	manifestList chan RequestLayerInfo
	fs           *FileServer
	WorkerGroup  *WorkerGroup
}

func (s *ScannerImageCacheService) AddLayerRecord(rq *RequestLayerInfo) {
	ly := &LayerInfo{
		refCount:   1,
		status:     LayerNotPull,
		url:        rq.URL,
		digest:     rq.Digest,
		repository: rq.Repository,
		username:   rq.Username,
		password:   rq.Password,
		skipTLS:    rq.SkipTLS,
		flag:       make(chan int),
	}
	s.LayerQueue.Set(ly)
}

func (s *ScannerImageCacheService) AddManifestTask(ctx context.Context, rq *RequestLayerInfo) {
	s.manifestList <- *rq
}

func (s *ScannerImageCacheService) WaitLayerPulled(digest string) error {
	cnt := 0
	// 防止卡死
	for cnt < consts.DefaultPullLayerTimeout*60 {
		lay, ok := s.LayerQueue.Get(digest)
		if ok && (lay.status == LayerPulled || lay.status == LayerPullErr) {
			return nil
		}
		cnt++
		time.Sleep(time.Second)
	}
	return fmt.Errorf("pull layer timeout :%s", digest)
}

func (s *ScannerImageCacheService) NotifyLayerPulled(digest string) error {
	s.LayerQueue.NotifyLayerPulled(digest)
	return nil
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
	logging.Get().Debug().Msgf("server resp %v", rsp)
}

func (s *ScannerImageCacheService) ResponseOK(lay *LayerInfo, ctx *gin.Context) {
	LayerHTTPPath := fmt.Sprintf("http://%s:%d/%s/%s", s.fs.externalIP, s.fs.port, lay.digest, LayerFileName)
	rsp := ResponseLayerInfo{
		Code:       0,
		Msg:        "ok",
		URL:        LayerHTTPPath,
		Digest:     lay.digest,
		Repository: lay.repository,
		LayerURL:   lay.layerURL,
	}

	ctx.JSON(http.StatusOK, rsp)
}

func (s *ScannerImageCacheService) ResponseErr(lay string, ctx *gin.Context) {

	rsp := ResponseLayerInfo{
		Code: 1,
		Msg:  fmt.Sprintf("get layer:%s info err,not get layer", lay),
		// URL:      lay.url,
		// LayerURL: lay.layerURL,
		Digest: lay,
	}

	ctx.JSON(http.StatusBadRequest, rsp)
}

// url : http://0.0.0.0:xxx/layer?repository=xxx&digest=xxx&url=xxx
func (s *ScannerImageCacheService) handleDelete(ctx *gin.Context) {
	// repository 	:= ctx.Query("repository")
	digest := ctx.Query("digest")
	logging.Get().Debug().Msgf("get delete req,digest %s", digest)

	if !s.LayerQueue.Exist(digest) {
		s.ResponseCodeAndMsg(1, "not find layer record", digest, ctx)
		return
	}
	s.LayerQueue.Dec(digest)

	// delete layer from file server
	if s.LayerQueue.NeedDelete(digest) {
		s.LayerQueue.Delete(digest)
		if err := s.fs.DeleteFile(digest); err != nil {
			logging.Get().Err(err).Msgf("delete layer file err,digest %s", digest)
		}
	} else {
		logging.Get().Debug().Msgf("digest %s still has ref,no delete", digest)
	}

	s.ResponseCodeAndMsg(0, "dec layer ref-count ok", digest, ctx)
}

func (s *ScannerImageCacheService) handleGet(ctx *gin.Context) {
	logging.Get().Info().Msgf("local layer manage get request")
	ctx.JSON(200, gin.H{
		"message": "pong",
	})
}

func (s *ScannerImageCacheService) handleClearCache(ctx *gin.Context) {
	logging.Get().Info().Msgf("local layer manage get ClearCache request")
	ctx.JSON(200, gin.H{
		"message": "pong",
	})
}

func (s *ScannerImageCacheService) handleFindBlob(ctx *gin.Context, repository string, refer string) {
	// repository := ctx.Param("name")
	fp := filepath.Join(s.fs.rootPath, "data", refer)
	fpLayer := "FileServerCache/" + fp + "/layer.tar"
	if !FileExists(fpLayer) {
		fpManifest := "FileServerCache/" + fp + "/" + refer + ".json"
		if !FileExists(fpManifest) {
			logging.Get().Error().Msgf("file not exist %v", fpManifest)
			ctx.Status(400)
			return
		}
	}
	fp = fpLayer
	ctx.File(fp)
	// ctx.File("/worker1/tensornavigator/test/cmd/scanner/component/layer_manage/" + fp)
}

func (s *ScannerImageCacheService) handleFindManifest(ctx *gin.Context, repository string, refer string) {

	fp := filepath.Join(s.fs.rootPath, "manifests", repository, refer)
	fp = filepath.Join(fp, "manifest.json")
	fp = "FileServerCache/" + fp
	if !FileExists(fp) {
		logging.Get().Error().Msgf("not found %v", fp)
		ctx.Status(404)
		return
	}
	manifestJSON, err := os.ReadFile(fp)
	if err != nil {
		logging.Get().Err(err)
		ctx.Status(404)
		return
	}

	ctx.String(200, string(manifestJSON))
}

func (s *ScannerImageCacheService) handleManifest(ctx *gin.Context) {
	var body []byte
	if ctx.Request.Body != nil {
		if data, err := ioutil.ReadAll(ctx.Request.Body); err == nil {
			body = data
		}
	}
	if len(body) == 0 {
		if err := ctx.AbortWithError(http.StatusBadRequest, fmt.Errorf("empty body")); err != nil {
			logging.Get().Err(err).Msg("failed to abort request")
		}
		return
	}
	rq := &RequestLayerInfo{}
	err := json.Unmarshal(body, rq)
	if err != nil {
		logging.Get().Err(err).Msgf(" json unmarshal err")

		ctx.JSON(http.StatusBadRequest, ResponseLayerInfo{
			Code:       1,
			Msg:        err.Error(),
			Repository: rq.Repository,
			Digest:     rq.Digest,
		})
	}

	rq.Response = make(chan string, 1)
	s.AddManifestTask(ctx, rq)
	str := <-rq.Response
	if strings.Contains(str, "GetManifestError") {
		ctx.JSON(400, str)
	} else {
		ctx.String(200, "%s", str)
	}
}

// url : http://0.0.0.0:xxx/layer?
func (s *ScannerImageCacheService) handlePost(ctx *gin.Context) {
	logging.Get().Debug().Msg("local layer manage get post request")

	var body []byte
	if ctx.Request.Body != nil {
		if data, err := ioutil.ReadAll(ctx.Request.Body); err == nil {
			body = data
		}
	}

	if len(body) == 0 {
		if err := ctx.AbortWithError(http.StatusBadRequest, fmt.Errorf("empty body")); err != nil {
			logging.Get().Err(err).Msgf("failed to abort request")
		}
		return
	}

	rq := &RequestLayerInfo{}
	err := json.Unmarshal(body, rq)
	if err != nil {
		logging.Get().Err(err).Msgf(" json unmarshal err")

		ctx.JSON(http.StatusBadRequest, ResponseLayerInfo{
			Code:       1,
			Msg:        err.Error(),
			Repository: rq.Repository,
			Digest:     rq.Digest,
		})
	}

	logging.Get().Debug().Msgf("get request %+v", rq)

	// check if already pulled
	if s.LayerQueue.Exist(rq.Digest) {
		logging.Get().Debug().Msgf("layer %s exist", rq.Digest)
		s.LayerQueue.Inc(rq.Digest)
		if s.LayerQueue.Pulled(rq.Digest) {
			lay, exit := s.LayerQueue.Get(rq.Digest)
			if !exit {
				logging.Get().Error().Str("layer", rq.Digest).Msg("layer not exit")
				s.ResponseErr(rq.Digest, ctx)
				return
			}
			s.ResponseOK(lay, ctx)
			return
		}
	} else {
		logging.Get().Debug().Msgf("add record ")
		s.AddLayerRecord(rq)
	}

	// check if layer has been pulled
	if err := s.WaitLayerPulled(rq.Digest); err != nil {
		s.ResponseErr(rq.Digest, ctx)
		return
	}

	logging.Get().Debug().Msgf("layer %s check end", rq.Digest)

	lay, b := s.LayerQueue.Get(rq.Digest)
	if b && lay.status == LayerPulled {
		s.ResponseOK(lay, ctx)
		return
	}

	s.ResponseErr(rq.Digest, ctx)
}

func (s *ScannerImageCacheService) OpenGinLog() {
	// test log
	gin.DisableConsoleColor()

	// Logging to a file.
	logpath := filepath.Join(os.TempDir(), "ginlog.log")
	logging.Get().Info().Msgf("gin log path %s", logpath)
	f, _ := os.Create(logpath)
	gin.DefaultWriter = io.MultiWriter(f)
}

func (s *ScannerImageCacheService) CreateServer() {
	// test
	// s.OpenGinLog()
	server := gin.New()

	server.GET("/v2/*xx", func(ctx *gin.Context) {
		if strings.LastIndex(ctx.Request.RequestURI, "/blobs/") > 0 {
			v2Index := strings.Index(ctx.Request.RequestURI, "/v2/")
			blobIndex := strings.LastIndex(ctx.Request.RequestURI, "/blobs/")
			respository := ctx.Request.RequestURI[v2Index+4 : blobIndex]
			refer := ctx.Request.RequestURI[blobIndex+7:]
			// fmt.Printf("%v %v\n", respository, refer)
			s.handleFindBlob(ctx, respository, refer)
		}

		if strings.LastIndex(ctx.Request.RequestURI, "/manifests/") > 0 {
			v2Index := strings.Index(ctx.Request.RequestURI, "/v2/")
			manifestIndex := strings.LastIndex(ctx.Request.RequestURI, "/manifests/")
			respository := ctx.Request.RequestURI[v2Index+4 : manifestIndex]
			refer := ctx.Request.RequestURI[manifestIndex+11:]
			// fmt.Printf("%v %v\n", respository, refer)
			s.handleFindManifest(ctx, respository, refer)
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
	// for test
	server.GET(httpRequestPath, func(ctx *gin.Context) {
		s.handleGet(ctx)
	})
	// clearCache
	server.GET("/clearCache", func(ctx *gin.Context) {
		s.handleClearCache(ctx)
	})
	s.server = server
}

func (s *ScannerImageCacheService) StartServer() {
	go func() {
		address := fmt.Sprintf("%s:%d", s.serverIP, s.port)
		logging.Get().Info().Msgf("image cache start server :%s", address)
		err := s.server.Run(address)
		if err != nil {
			logging.Get().Err(err).Msg("start s server err")
		}
		logging.Get().Info().Msg("image cache server end")
	}()

	logging.Get().Info().Msgf("image cache service listen on port %d", s.port)
}

func (s *ScannerImageCacheService) FindAndModifyPullTask() LayerInfo {
	return s.LayerQueue.GetNeedPullLayer()
}

func (s *ScannerImageCacheService) UpdateTaskStatusAndLayerURL(digest, layerURL string, status int) error {
	return s.LayerQueue.UpdateTask(digest, layerURL, status)
}

func (s *ScannerImageCacheService) Start(ctx context.Context) error {
	// start inner registry server
	s.CreateServer()
	logging.Get().Info().Msg("image cache create server ok")

	s.StartServer()

	// start file server
	err := s.fs.Run(s.ctx)
	if err != nil {
		logging.Get().Err(err).Msg("start file server failed")
		return err
	}

	// run worker
	s.WorkerGroup.Run()

	logging.Get().Info().Msg("start image cache service ok")
	return nil
}

func (s *ScannerImageCacheService) Stop(ctx context.Context) error {
	// if err := s.server.Run(ctx); err != nil {
	//	logging.GetLogger().Err(err).Msg("image cache server stop err")
	//	return err
	// }
	logging.Get().Info().Msg("image cache server stop")
	return nil
}

func init() {
	err := register.Register(serviceName, newService)
	if err != nil {
		logging.Get().Err(err).Str("serviceName", serviceName).Msg("int service err")
	}
}

func newService(config register.ScannerServiceConfig) (register.ScannerService, error) {
	s := &ScannerImageCacheService{
		serverIP:     innerRegistryIP,
		port:         innerRegistryPort,
		manifestList: make(chan RequestLayerInfo, 100),
	}
	s.config.CacheServerPort = config.Options.ImageCacheServerPort
	s.config.CacheServerIP = config.Options.ImageCacheServerIP

	fs, _ := NewFileServer(context.Background(), FileServerRootDir, s.config.CacheServerIP, innerRegistryIP, s.config.CacheServerPort)
	s.LayerQueue = NewLayerQueue()
	s.fs = fs

	wg, _ := NewWorkerGroup(s, maxWorkerNum)
	s.WorkerGroup = wg
	logging.Get().Info().Msg("new image cache service ok")
	return s, nil
}
