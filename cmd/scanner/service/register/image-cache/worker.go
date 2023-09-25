package imagecache

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	dig "github.com/opencontainers/go-digest"
	"gitlab.com/security-rd/go-pkg/logging"
)

const (
	RegistryConnectInterval = 2 // unit: second
	RegistryConnectRetryCnt = 3
)

type Worker struct {
	id   int
	llms *ScannerImageCacheService
	rc   *RegistryClient
	wg   *WorkerGroup
}

// // RegistryConnectInfo user+registry-url make unique registry client
// type RegistryConnectInfo struct {
//	username string
//	url string
// }

type WorkerGroup struct {
	workerNum int
	workers   []*Worker
	swg       sync.WaitGroup
	llms      *ScannerImageCacheService
	// registerClientMap *sync.Map
}

func NewWorkerGroup(llms *ScannerImageCacheService, workerNum int) (*WorkerGroup, error) {
	wg := &WorkerGroup{
		llms:      llms,
		workerNum: workerNum,
		// registerClientMap: new(sync.Map),
	}
	return wg, nil
}

func (wg *WorkerGroup) Run() {
	wg.initWorkers()
	go wg.startWorker()
}

func (wg *WorkerGroup) initWorkers() {
	wg.workers = make([]*Worker, wg.workerNum*2)
	for i := 0; i < wg.workerNum*2; i++ {
		wg.workers[i] = &Worker{
			id:   i,
			llms: wg.llms,
			wg:   wg,
			rc:   nil,
		}
	}
}

func (wg *WorkerGroup) startWorker() {
	for i := 0; i < wg.workerNum; i++ {
		wg.swg.Add(1)
		go func(i int) {
			defer func() {
				if r := recover(); r != nil {
					logging.Get().Error().Msgf("image cache server worker panic : %v. stack: %s", r, debug.Stack())
				}
			}()
			defer wg.swg.Done()
			wg.workerRun(i, &wg.swg)
		}(i)
		wg.swg.Add(1)
		go func(i int) {
			defer func() {
				if r := recover(); r != nil {
					logging.Get().Error().Msgf("image cache server worker panic : %v. stack: %s", r, debug.Stack())
				}
			}()
			defer wg.swg.Done()
			wg.workerManiRun(i, &wg.swg)
		}(i + wg.workerNum)
	}
	wg.swg.Wait()
}

func (wg *WorkerGroup) workerManiRun(i int, swg *sync.WaitGroup) {
	logging.Get().Info().Int("workerId", i).Msg("image cache worker manifest task running")
	wg.workers[i].doManifestTask(swg)
}

func (wg *WorkerGroup) workerRun(i int, swg *sync.WaitGroup) {
	logging.Get().Info().Int("workerId", i).Msg("image cache worker normal task running")
	wg.workers[i].doTask(swg)
}

func (w *Worker) createRegistryClient(username, password, repository, url string, skipTLS bool) (err2 error) {
	for i := 0; i < RegistryConnectRetryCnt; i++ {
		rc, err := NewRegistryClient(username, password, repository, url, skipTLS)
		if err == nil {
			w.rc = rc
			return nil
		}
		err2 = err
		time.Sleep(time.Duration(RegistryConnectInterval) * time.Second)
	}

	return err2
}

// for test
// func (w *Worker) fakeDownloadBlob() (io.ReadCloser, error) {

// 	r := ioutil.NopCloser(strings.NewReader("hello world")) // r type is io.ReadCloser

//		return r, nil
//	}
func (w *Worker) doTask(wg *sync.WaitGroup) {

	errMsg := ""
	for {
		time.Sleep(time.Duration(3) * time.Second)

		// get to-pull task
		task, err := w.llms.FindAndModifyPullTask()
		if err != nil {
			logging.Get().Err(err).Msgf("worker %d get task err", w.id)
			continue
		}

		// not task available
		if len(task.digest) == 0 {
			continue
		}

		logging.Get().Info().Msgf("worker %d get task url: %v, refCount:%v ,username:%v", w.id, task.url, task.refCount, task.username)

		if w.rc == nil {
			// create registry client
			err = w.createRegistryClient(task.username, task.password, task.repository, task.url, task.skipTLS)
			// rc,err := w.wg.LoadOrSaveRegistryClient(task.username,task.password,task.repository,task.url,task.skipTls)
			if err != nil {
				errMsg = fmt.Sprintf("download layer err,repo %s ,digest %s,err %v", task.repository, task.digest, err)
				logging.Get().Err(err).Msgf("worker %d create registry client err:%s", w.id, errMsg)

				// reset task status,wait other worker pick it
				err := w.llms.UpdateTaskStatusAndLayerURL(task.digest, "", LayerPullErr)
				if err != nil {
					logging.Get().Err(err).Msgf("worker %d create registry client UpdateTaskStatusAndLayerURL", w.id)
					err = w.llms.NotifyLayerPulled(task.digest)
					if err != nil {
						logging.Get().Err(err).Msgf("worker %d create registry client  NotifyLayerPulled err:%s", w.id, err)
					}
				}

				continue
			}
		}

		// pull
		d := dig.NewDigestFromHex(strings.Split(task.digest, ":")[0], strings.Split(task.digest, ":")[1])
		// reader, err := w.rc.registryClient.DownloadBlob(task.repository, d)
		reader, err := w.rc.DownloadBlob(task.repository, d)
		if err != nil {
			err = w.createRegistryClient(task.username, task.password, task.repository, task.url, task.skipTLS)
			if err == nil {
				reader, err = w.rc.DownloadBlob(task.repository, d)
			}
		}
		if err != nil {
			errMsg = fmt.Sprintf("download layer err,repo %s ,digest %s,err %v", task.repository, task.digest, err)
			logging.Get().Err(err).Msgf("worker %d pull task err:%s", w.id, errMsg)

			// update task to pull err
			err := w.llms.UpdateTaskStatusAndLayerURL(task.digest, "", LayerPullErr)
			if err != nil {
				logging.Get().Err(err).Msgf("worker %d pull task UpdateTaskStatusAndLayerURL", w.id)
				err = w.llms.NotifyLayerPulled(task.digest)
				if err != nil {
					logging.Get().Err(err).Msgf("worker %d pull tasks  NotifyLayerPulled", w.id)
				}
			}
			continue
		}

		// save to file server
		fullFilePath, err := w.llms.fs.SaveFile(task.digest, reader)
		reader.Close()
		if err != nil {
			inerr := w.llms.UpdateTaskStatusAndLayerURL(task.digest, "", LayerPullErr)
			if inerr != nil {
				logging.Get().Err(inerr).Msgf("worker %d create registry client UpdateTaskStatusAndLayerURL", w.id)
			}
			logging.Get().Err(err).Msgf("worker %d pull task err.repository %s,digest %s", w.id, task.repository, task.digest)
		} else {
			// update task to succeed
			inerr := w.llms.UpdateTaskStatusAndLayerURL(task.digest, fullFilePath, LayerPulled)
			if inerr != nil {
				logging.Get().Err(inerr).Msgf("worker %d create registry client UpdateTaskStatusAndLayerURL", w.id)
			}
			logging.Get().Debug().Msgf("worker %d pull task ok.repository %s,digest %s,path %s", w.id, task.repository, task.digest, fullFilePath)
		}
		// notify layer pulled
		err = w.llms.NotifyLayerPulled(task.digest)
		if err != nil {
			logging.Get().Err(err).Msgf("worker %d NotifyLayerPulled", w.id)
		}
	}

}

func (w *Worker) doManifestTask(wg *sync.WaitGroup) {
	for { // nolint
		select {
		case task := <-w.llms.manifestList:
			logging.Get().Info().Msg("get manifest task")
			w.saveManifest(task)
		}
	}
}

func (w *Worker) saveManifest(task RequestLayerInfo) {
	if w.rc == nil || w.rc.url != task.URL {
		// create registry client
		err := w.createRegistryClient(task.Username, task.Password, task.Repository, task.URL, task.SkipTLS)
		// rc,err := w.wg.LoadOrSaveRegistryClient(task.username,task.password,task.repository,task.url,task.skipTls)
		if err != nil {
			logging.Get().Err(err).Msg("create registry client err")
			task.Response <- fmt.Sprintf("GetManifestError %v", err)
			return
		}
	}
	manifest, err := w.rc.readManifest(context.Background(), "v2", task.Repository, task.Tag)
	if err != nil {
		logging.Get().Err(err).Msg("read V2 manifest err will test V1 manifest")
		manifest, err = w.rc.readManifest(context.Background(), "v1", task.Repository, task.Tag)
		if err != nil {
			logging.Get().Err(err).Msg("read V1 manifest err will return error")
			task.Response <- fmt.Sprintf("GetManifestError %v", err)
			return
		}
	}

	fp := filepath.Join(w.llms.fs.rootPath, "manifests", task.Repository+"/"+task.Tag)
	fp = "FileServerCache/" + fp
	err = os.MkdirAll(fp, 0777)
	if err != nil {
		logging.Get().Err(err).Str("manifestPath", fp).Msg("make manifest dir err")
		task.Response <- fmt.Sprintf("make manifest dir err %v", err)
		return
	}
	fp = filepath.Join(fp, "manifest.json")
	err = os.WriteFile(fp, manifest, 0600)
	if err != nil {
		logging.Get().Err(err).Msg("write manifest.json err")
		task.Response <- fmt.Sprintf("write manifest json err %v", err)
		return
	}
	task.Response <- string(manifest)
}

func FileExists(path string) bool {
	_, err := os.Stat(path) // os.Stat获取文件信息

	if err != nil {
		return os.IsExist(err)
	}

	return true
}
