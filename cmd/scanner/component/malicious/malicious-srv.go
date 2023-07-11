package malicious

import (
	"errors"
	"path/filepath"
	"sync"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

var (
	singleServer   MaliciousServer
	once           sync.Once
	DefaultTaskNum = 20
)

type ScanData struct {
	FilePath string
	Result   chan string
}

type MaliciousServer struct {
	Cs     *ClamavScanner
	ch     chan ScanData
	Updata UpdateService
	Lock   sync.RWMutex
}

func NewMaliciousServer() (*MaliciousServer, error) {
	once.Do(func() {
		err := InitClamav()
		if err != nil {
			logging.GetLogger().Err(err).Msgf("init Clamav error")
			return
		}
		singleServer.Cs = NewClamavScanner()
		err = singleServer.Cs.InitClEngine()
		if err != nil {
			logging.GetLogger().Err(err).Msgf("init clamav engine error")
			return
		}
		singleServer.ch = make(chan ScanData, DefaultTaskNum) // 之前多线程是12，可能这个值要调低些
	})
	return &singleServer, nil
}

func GetMaliciousServer() *MaliciousServer {
	return &singleServer
}

func (m *MaliciousServer) LoadDB(path string) error {
	if m.Updata.DbPath == "" {
		return errors.New("not have dbPath in updata service")
	}
	m.Lock.Lock()
	defer m.Lock.Unlock()
	if m.Cs.engine != nil {
		err := m.Cs.CloseClEngine()
		if err != nil {
			return err
		}
		err = m.Cs.InitClEngine()
		if err != nil {
			return err
		}
	}
	_, err := m.Cs.Load(path, DbDefaultOpt)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("init Clamav error")
		return err
	}
	err = m.Cs.Compile()
	if err != nil {
		logging.GetLogger().Err(err).Msgf("Compile Clamav error")
		return err
	}
	m.Updata.DbPath = path
	return nil
}

func (m *MaliciousServer) Scan(filepath string) string {
	m.Lock.RLock()
	defer m.Lock.RUnlock()
	data := ScanData{FilePath: filepath, Result: make(chan string)}
	m.ch <- data
	return <-data.Result
}

func (m *MaliciousServer) AddTask(queue chan struct{}, data ScanData) {
	defer func() {
		<-queue
	}()
	virusName, _, err := m.Cs.ScanFile(data.FilePath)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("scan virus error file :%v", data.FilePath)
		data.Result <- ""
	}
	if virusName != "" {
		logging.GetLogger().Info().Msgf("clamav scan virusName %v", virusName)
	}
	data.Result <- virusName
}

func (m *MaliciousServer) autoScan() {
	taskQueue := make(chan struct{}, DefaultTaskNum)
	for {
		select {
		case data := <-m.ch:
			taskQueue <- struct{}{} // 限制同时并发数
			go m.AddTask(taskQueue, data)
		}
	}
}

func (m *MaliciousServer) Run() {
	go m.autoScan()
	for data := range m.Updata.PathCh {
		logging.GetLogger().Info().Msgf("clamav up db path %v", data.DBPath)
		err := m.LoadDB(data.DBPath)
		if err != nil {
			data.Result <- false
			serr := m.LoadDB(filepath.Join(m.Updata.DbPath, "clamav"))
			if serr != nil {
				logging.GetLogger().Err(err).Msgf("load old db error ,will close clamav engine ,please check your db")
				m.Cs.CloseClEngine()
			}
		}
		data.Result <- true
		// TODO 入库
	}
}
