package layermanage

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	json "github.com/json-iterator/go"
	"gitlab.com/security-rd/go-pkg/logging"
)

const (
	httpRequestPath = "/layer"
)

// layer file status
const (
	LayerNotPull = iota
	LayerPulled
	LayerPulling
	LayerPullErr
)

// type ManifestInfo struct {
// digest     string
// repository string
// manifest   []string
// username   string
// password   string
// skipTls    string
// }

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
	Repository string `json:"repository"`
	Digest     string `json:"digest"`
	URL        string `json:"url"` // registry url
	Username   string `json:"username"`
	Password   string `json:"password"`
	SkipTLS    bool   `json:"skiptls"`
}

type ResponseLayerInfo struct {
	Code       int    `json:"code"`
	Msg        string `json:"msg"`
	URL        string `json:"url"`
	LayerURL   string `json:"layer-url"`
	Digest     string `json:"digest"`
	Repository string `json:"repository"`
}

// type CacheCounter struct {
// 	cacheHit  int64
// 	cacheMiss int64
// }

type LocalLayerManageSrv struct {
	ctx       context.Context
	serverIP  string
	port      int
	server    *gin.Engine
	layerList map[string]*LayerInfo // digest->layer info
	// manifestList map[string]*ManifestInfo //digest->manifest info
	taskLock sync.Mutex
	// manifestLock sync.Mutex
	// cacheCounter CacheCounter
	fs          *FileServer
	WorkerGroup *WorkerGroup
}

func NewLocalLayerManageSrv(ctx context.Context, serverIP string, port, fsPort int, fsExternalIP string) (*LocalLayerManageSrv, error) {
	l := make(map[string]*LayerInfo)
	fs, _ := NewFileServer(ctx, FileServerRootDir, fsExternalIP, serverIP, fsPort)
	llms := &LocalLayerManageSrv{
		ctx:       ctx,
		serverIP:  serverIP,
		port:      port,
		layerList: l,
		fs:        fs,
		//	cacheCounter: CacheCounter{},
	}
	wg, _ := NewWorkerGroup(llms, 5)
	llms.WorkerGroup = wg
	return llms, nil
}

func (llms *LocalLayerManageSrv) Run() error {
	logging.Get().Info().Msg("llms run")

	// start server
	llms.CreateServer()
	llms.StartServer()

	// start file server
	err := llms.fs.Run(llms.ctx)
	if err != nil {
		return err
	}
	// run worker
	llms.WorkerGroup.Run()

	return nil
}

func (llms *LocalLayerManageSrv) IsLayerExist(digest string) bool {
	_, ok := llms.layerList[digest]
	return ok
}

func (llms *LocalLayerManageSrv) IsLayerPulled(digest string) bool {
	if llms.IsLayerExist(digest) && llms.layerList[digest].status == LayerPulled {
		return true
	}
	return false
}

func (llms *LocalLayerManageSrv) IncLayerRefCount(digest string) {
	llms.layerList[digest].refCount++
	logging.Get().Info().Msgf("digest %s,ADD layer refcount(%d)  ", digest, llms.layerList[digest].refCount)
}

func (llms *LocalLayerManageSrv) IsLayerNoRef(digest string) bool {
	return llms.layerList[digest].refCount == 0

}

func (llms *LocalLayerManageSrv) DecLayerRefCount(digest string) error {
	_, ok := llms.layerList[digest]
	if !ok {
		return fmt.Errorf("not find layer,digest %s", digest)
	}
	if llms.layerList[digest].refCount <= 0 {
		// some err,should have been deleted
		logging.Get().Error().Msgf("digest %s,layer refcount(%d) <=0 ", digest, llms.layerList[digest].refCount)
		// still return nil,deleted by caller
		return nil
	}
	llms.layerList[digest].refCount--
	logging.Get().Info().Msgf("DecRef refcount(%d) ", llms.layerList[digest].refCount)
	return nil
}

func (llms *LocalLayerManageSrv) AddLayerRecord(rq *RequestLayerInfo) {
	llms.layerList[rq.Digest] = &LayerInfo{
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
}

func (llms *LocalLayerManageSrv) WaitLayerPulled(digest string) {
	for {
		llms.taskLock.Lock()
		if _, ok := llms.layerList[digest]; !ok {
			logging.Get().Info().Msgf("wait layer pulled,layer %s not exist", digest)
			llms.taskLock.Unlock()
			break
		}
		if llms.layerList[digest].status == LayerPulled || llms.layerList[digest].status == LayerPullErr {
			llms.taskLock.Unlock()
			break
		}
		llms.taskLock.Unlock()

		time.Sleep(time.Duration(20) * time.Millisecond)
	}
}

func (llms *LocalLayerManageSrv) NotifyLayerPulled(digest string) error {
	return nil
	// if _,ok := llms.layerList[digest];!ok {
	//	return fmt.Errorf("layer %s not exist",digest)
	// }
	// llms.layerList[digest].flag <- 1
	// log.Info().Msgf("notify digest %s end",digest)
	// return nil
}

func (llms *LocalLayerManageSrv) ResponseCodeAndMsg(code int, msg, digest string, ctx *gin.Context) {
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
	logging.Get().Info().Msgf("server resp %v", rsp)
}

func (llms *LocalLayerManageSrv) ResponseOK(digest string, ctx *gin.Context) {
	LayerHTTPPath := fmt.Sprintf("http://%s:%d/%s/%s", llms.fs.externalIP, llms.fs.port, digest, LayerFileName)
	rsp := ResponseLayerInfo{
		Code:       0,
		Msg:        "ok",
		URL:        LayerHTTPPath,
		Digest:     digest,
		Repository: llms.layerList[digest].repository,
		LayerURL:   llms.layerList[digest].layerURL,
	}
	ctx.JSON(http.StatusOK, rsp)
}

func (llms *LocalLayerManageSrv) ResponseErr(digest string, ctx *gin.Context) {
	rsp := ResponseLayerInfo{
		Code:     1,
		Msg:      fmt.Sprintf("get layer info err: %d", llms.layerList[digest].status),
		URL:      llms.layerList[digest].url,
		LayerURL: llms.layerList[digest].layerURL,
		Digest:   digest,
	}

	ctx.JSON(http.StatusBadRequest, rsp)
}

// url : http://0.0.0.0:xxx/layer?repository=xxx&digest=xxx&url=xxx
func (llms *LocalLayerManageSrv) handleDelete(ctx *gin.Context) {
	// repository 	:= ctx.Query("repository")
	digest := ctx.Query("digest")
	logging.Get().Info().Msgf("get delete req,digest %s", digest)

	llms.taskLock.Lock()
	if !llms.IsLayerExist(digest) {
		llms.taskLock.Unlock()
		llms.ResponseCodeAndMsg(1, "not find layer record", digest, ctx)
		return
	}

	// dec refcount
	err := llms.DecLayerRefCount(digest)
	if err != nil {
		logging.Get().Err(err).Msgf("delete layer file refcount err,digest %s", digest)
	}

	// delete layer from file server
	if llms.IsLayerNoRef(digest) {
		delete(llms.layerList, digest)
		err = llms.fs.DeleteFile(digest)
		if err != nil {
			logging.Get().Err(err).Msgf("delete layer file err,digest %s", digest)
		}
	} else {
		logging.Get().Info().Msgf("digest %s still has ref,no delete", digest)
	}

	// delete from layerlist
	// delete(llms.layerList, digest)

	llms.taskLock.Unlock()

	llms.ResponseCodeAndMsg(0, "dec layer ref-count ok", digest, ctx)
}

func (llms *LocalLayerManageSrv) handleGet(ctx *gin.Context) {
	logging.Get().Info().Msgf("local layer manage get request")
	ctx.JSON(200, gin.H{
		"message": "pong",
	})
}

func (llms *LocalLayerManageSrv) handleClearCache(ctx *gin.Context) {
	logging.Get().Info().Msgf("local layer manage get ClearCache request")
	ctx.JSON(200, gin.H{
		"message": "pong",
	})
}

// url : http://0.0.0.0:xxx/layer?
func (llms *LocalLayerManageSrv) handlePost(ctx *gin.Context) {
	logging.Get().Info().Msgf("local layer manage get post request")

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
		logging.Get().Error().Msgf(" json unmarshal err %v", err)

		ctx.JSON(http.StatusBadRequest, ResponseLayerInfo{
			Code:       1,
			Msg:        err.Error(),
			Repository: rq.Repository,
			Digest:     rq.Digest,
		})
	}

	llms.taskLock.Lock()
	// check if already pulled
	if llms.IsLayerExist(rq.Digest) {
		logging.Get().Info().Msgf("layer %s exist", rq.Digest)
		llms.IncLayerRefCount(rq.Digest)
		llms.taskLock.Unlock()
		if llms.IsLayerPulled(rq.Digest) {
			// pulled, return
			llms.ResponseOK(rq.Digest, ctx)
			return
		}
		// if exist but not pulled,go to WaitLayerPulled
	} else {
		logging.Get().Info().Msgf("add record ")

		// not find,add new record
		llms.AddLayerRecord(rq)
		llms.taskLock.Unlock()
	}

	logging.Get().Info().Msgf("wait layer pulled,refcount %d", llms.layerList[rq.Digest].refCount)

	// check if layer has been pulled
	llms.WaitLayerPulled(rq.Digest)

	logging.Get().Info().Msgf("layer %s check end", rq.Digest)

	if llms.layerList[rq.Digest].status == LayerPulled {
		llms.ResponseOK(rq.Digest, ctx)
	} else {
		llms.ResponseErr(rq.Digest, ctx)
	}
}

func (llms *LocalLayerManageSrv) OpenGinLog() {
	// test log
	gin.DisableConsoleColor()

	// Logging to a file.
	logpath := filepath.Join(os.TempDir(), "ginlog.log")
	logging.Get().Info().Msgf("gin log path %s", logpath)
	f, _ := os.Create(logpath)
	gin.DefaultWriter = io.MultiWriter(f)
}

func (llms *LocalLayerManageSrv) CreateServer() {
	// test
	llms.OpenGinLog()

	server := gin.New()
	server.POST(httpRequestPath, func(ctx *gin.Context) {
		llms.handlePost(ctx)
	})
	server.DELETE(httpRequestPath, func(ctx *gin.Context) {
		llms.handleDelete(ctx)
	})
	// for test
	server.GET(httpRequestPath, func(ctx *gin.Context) {
		llms.handleGet(ctx)
	})
	// clearCache
	server.GET("/clearCache", func(ctx *gin.Context) {
		llms.handleClearCache(ctx)
	})
	llms.server = server

}

func (llms *LocalLayerManageSrv) StartServer() {
	go func() {
		address := fmt.Sprintf("%s:%d", llms.serverIP, llms.port)
		err := llms.server.Run(address)
		if err != nil {
			logging.Get().Err(err).Msgf("start llms server err")
		}
	}()

	logging.Get().Info().Msgf("Server local layer manage srv  port %d", llms.port)

}

func (llms *LocalLayerManageSrv) FindAndModiyPullTask() (LayerInfo, error) {
	res := LayerInfo{}
	llms.taskLock.Lock()
	for k, v := range llms.layerList {
		if v.status == LayerNotPull {
			res.username = v.username
			res.password = v.password
			res.skipTLS = v.skipTLS
			res.digest = v.digest
			res.repository = v.repository
			res.url = v.url
			// set task to pulling
			llms.layerList[k].status = LayerPulling
			res.status = LayerPulling
			break
		}
	}
	llms.taskLock.Unlock()

	return res, nil
}

func (llms *LocalLayerManageSrv) UpdateTaskStatusAndLayerURL(digest, layerURL string, status int) error {
	if _, ok := llms.layerList[digest]; !ok {
		return fmt.Errorf("not found layer %s", digest)
	}
	llms.taskLock.Lock()
	llms.layerList[digest].status = status
	if len(layerURL) != 0 {
		llms.layerList[digest].layerURL = layerURL
	}
	llms.taskLock.Unlock()

	return nil
}
