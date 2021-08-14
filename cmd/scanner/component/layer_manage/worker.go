package layerManage

import (
	"fmt"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	dig "github.com/opencontainers/go-digest"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

const (
	RegistryConnectInterval = 2 //unit: second
	RegistryConnectRetryCnt = 3
)

type Worker struct {
	id   int
	llms *LocalLayerManageSrv
	rc   *RegistryClient
	wg   *WorkerGroup
}

//// RegistryConnectInfo user+registry-url make unique registry client
//type RegistryConnectInfo struct {
//	username string
//	url string
//}

type WorkerGroup struct {
	workerNum int
	workers   []*Worker
	swg       sync.WaitGroup
	llms      *LocalLayerManageSrv
	//registerClientMap *sync.Map
}

func NewWorkerGroup(llms *LocalLayerManageSrv, workerNum int) (*WorkerGroup, error) {
	wg := &WorkerGroup{
		llms:      llms,
		workerNum: workerNum,
		//registerClientMap: new(sync.Map),
	}
	return wg, nil
}

//func (wg *WorkerGroup) LoadOrSaveRegistryClient(username,password,repository,url string,skipTls bool) (*RegistryClient,error) {
//	rc,err := NewRegistryClient(username,password,repository,url,skipTls)
//	if err != nil {
//		return nil,err
//	}
//
//	v,ok := wg.registerClientMap.LoadOrStore(RegistryConnectInfo{username: username,url: url},rc)
//	if !ok {
//		//new key,first save,return new client
//		return rc,nil
//	}
//	//old key,already had client
//	return v.(*RegistryClient),nil
//}

func (wg *WorkerGroup) Run() {
	wg.initWorkers()
	go wg.startWorker()
}

func (wg *WorkerGroup) initWorkers() {
	wg.workers = make([]*Worker, wg.workerNum)
	for i := 0; i < wg.workerNum; i++ {
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
					logging.GetLogger().Error().Msgf("Layer_mannger Worker error : %v. stack: %s", r, debug.Stack())
				}
			}()
			defer wg.swg.Done()
			wg.workerRun(i, &wg.swg)
		}(i)
	}
	wg.swg.Wait()
}

func (wg *WorkerGroup) workerRun(i int, swg *sync.WaitGroup) {
	wg.workers[i].doTask(swg)
}

func (w *Worker) createRegistryClient(username, password, repository, url string, skipTls bool) (err2 error) {
	for i := 0; i < RegistryConnectRetryCnt; i++ {
		rc, err := NewRegistryClient(username, password, repository, url, skipTls)
		if err == nil {
			w.rc = rc
			return nil
		}
		err2 = err
		time.Sleep(time.Duration(RegistryConnectInterval) * time.Second)
	}

	return err2
}

//for test
// func (w *Worker) fakeDownloadBlob() (io.ReadCloser, error) {

// 	r := ioutil.NopCloser(strings.NewReader("hello world")) // r type is io.ReadCloser

// 	return r, nil
// }
func (w *Worker) doTask(wg *sync.WaitGroup) {

	errMsg := ""
	for {
		time.Sleep(time.Duration(3) * time.Second)

		//get to-pull task
		task, err := w.llms.FindAndModiyPullTask()
		if err != nil {
			log.Error().Msgf("worker %d get task err.%v", w.id, err)
			continue
		}

		//not task available
		if len(task.digest) == 0 {
			//log.Info().Msg("not available task,try next time")
			continue
		}

		log.Info().Msgf("worker %d get task: %+v", w.id, task)

		if w.rc == nil {
			//create registry client
			err = w.createRegistryClient(task.username, task.password, task.repository, task.url, task.skipTls)
			//rc,err := w.wg.LoadOrSaveRegistryClient(task.username,task.password,task.repository,task.url,task.skipTls)
			if err != nil {
				errMsg = fmt.Sprintf("download layer err,repo %s ,digest %s,err %v", task.repository, task.digest, err)
				log.Error().Msgf("worker %d create registry client err:%s", w.id, errMsg)

				//reset task status,wait other worker pick it
				err := w.llms.UpdateTaskStatusAndLayerUrl(task.digest, "", LayerPullErr)
				if err != nil {
					log.Error().Msgf("worker %d create registry client UpdateTaskStatusAndLayerUrl err:%s", w.id, err)
				}
				if err != nil {
					err = w.llms.NotifyLayerPulled(task.digest)
				}
				log.Error().Msgf("worker %d create registry client  NotifyLayerPulled err:%s", w.id, err)
				continue
			}
		}

		//pull
		d := dig.NewDigestFromHex(strings.Split(task.digest, ":")[0], strings.Split(task.digest, ":")[1])
		//reader, err := w.rc.registryClient.DownloadBlob(task.repository, d)
		reader, err := w.rc.DownloadBlob(task.repository, d)
		if err != nil {
			err = w.createRegistryClient(task.username, task.password, task.repository, task.url, task.skipTls)
			if err == nil {
				reader, err = w.rc.DownloadBlob(task.repository, d)
			}
		}
		if err != nil {
			errMsg = fmt.Sprintf("download layer err,repo %s ,digest %s,err %v", task.repository, task.digest, err)
			log.Error().Msgf("worker %d pull task err:%s", w.id, errMsg)

			//update task to pull err
			err := w.llms.UpdateTaskStatusAndLayerUrl(task.digest, "", LayerPullErr)
			if err != nil {
				log.Error().Msgf("worker %d pull task UpdateTaskStatusAndLayerUrl err:%s", w.id, err)
			}
			if err != nil {
				err = w.llms.NotifyLayerPulled(task.digest)
			}
			log.Error().Msgf("worker %d pull tasks  NotifyLayerPulled err:%s", w.id, err)
			continue
		}

		//save to file server
		fullFilePath, err := w.llms.fs.SaveFile(task.digest, reader)
		reader.Close()
		if err != nil {
			inerr := w.llms.UpdateTaskStatusAndLayerUrl(task.digest, "", LayerPullErr)
			if inerr != nil {
				log.Error().Msgf("worker %d create registry client UpdateTaskStatusAndLayerUrl err:%s", w.id, inerr)
			}
			log.Error().Msgf("worker %d pull task err.repository %s,digest %s,err %v", w.id, task.repository, task.digest, err)
		} else {
			// update task to succeed
			inerr := w.llms.UpdateTaskStatusAndLayerUrl(task.digest, fullFilePath, LayerPulled)
			if inerr != nil {
				log.Error().Msgf("worker %d create registry client UpdateTaskStatusAndLayerUrl err:%s", w.id, inerr)
			}
			log.Info().Msgf("worker %d pull task ok.repository %s,digest %s,path %s", w.id, task.repository, task.digest, fullFilePath)
		}
		//notify layer pulled
		err = w.llms.NotifyLayerPulled(task.digest)
		if err != nil {
			log.Error().Msgf("worker %d NotifyLayerPulled err.%v", w.id, err)
		}
	}

}
