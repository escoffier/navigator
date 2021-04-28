package layerManage

import (
	"fmt"
	"io"
	"io/ioutil"
	"strings"
	"sync"
	"time"

	dig "github.com/opencontainers/go-digest"
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

func (wg *WorkerGroup) initWorkers() error {
	wg.workers = make([]*Worker, wg.workerNum)
	for i := 0; i < wg.workerNum; i++ {
		wg.workers[i] = &Worker{
			id:   i,
			llms: wg.llms,
			wg:   wg,
			rc:   nil,
		}
	}
	return nil
}

func (wg *WorkerGroup) startWorker() error {
	for i := 0; i < wg.workerNum; i++ {
		wg.swg.Add(1)
		go wg.workerRun(i, &wg.swg)
	}
	wg.swg.Wait()
	return nil
}

func (wg *WorkerGroup) workerRun(i int, swg *sync.WaitGroup) error {
	wg.workers[i].doTask(swg)
	return nil
}

func (w *Worker) createRegistryClient(username, password, repository, url string, skipTls bool) error {
	var err error
	for i := 0; i < RegistryConnectRetryCnt; i++ {
		rc, err := NewRegistryClient(username, password, repository, url, skipTls)
		if err == nil {
			w.rc = rc
			return nil
		}
		time.Sleep(time.Duration(RegistryConnectInterval) * time.Second)
	}

	return err
}

//for test
func (w *Worker) fakeDownloadBlob() (io.ReadCloser, error) {

	r := ioutil.NopCloser(strings.NewReader("hello world")) // r type is io.ReadCloser

	return r, nil
}
func (w *Worker) doTask(wg *sync.WaitGroup) error {
	defer wg.Done()

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
				w.llms.UpdateTaskStatusAndLayerUrl(task.digest, "", LayerPullErr)
				w.llms.NotifyLayerPulled(task.digest)
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
			w.llms.UpdateTaskStatusAndLayerUrl(task.digest, "", LayerPullErr)
			w.llms.NotifyLayerPulled(task.digest)
			continue
		}

		//save to file server
		fullFilePath, err := w.llms.fs.SaveFile(task.digest, reader)
		reader.Close()
		if err != nil {
			w.llms.UpdateTaskStatusAndLayerUrl(task.digest, "", LayerPullErr)
			log.Error().Msgf("worker %d pull task err.repository %s,digest %s,err %v", w.id, task.repository, task.digest, err)
		} else {
			// update task to succeed
			w.llms.UpdateTaskStatusAndLayerUrl(task.digest, fullFilePath, LayerPulled)
			log.Info().Msgf("worker %d pull task ok.repository %s,digest %s,path %s", w.id, task.repository, task.digest, fullFilePath)
		}
		//notify layer pulled
		w.llms.NotifyLayerPulled(task.digest)
	}

	return nil
}
