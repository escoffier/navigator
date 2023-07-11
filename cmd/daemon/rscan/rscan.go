package rscan

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/containers/podman/v3/cmd/podman/utils"
	"github.com/hashicorp/go-multierror"
	"github.com/rs/zerolog"
	"gitlab.com/security-rd/go-pkg/logging"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/inotify"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/global"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/container"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo"
	"gitlab.com/piccolo_su/vegeta/pkg/avira"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/util"

	"golang.org/x/sync/semaphore"
	"k8s.io/utils/strings/slices"
)

const (
	ImageScopeEnv = "RSCAN_IMAGE_SCOPE"
)

type RuntimeScanner struct {
	sync.RWMutex
	stats             WatchStats
	watcher           *inotify.Watcher
	containerRootPath map[string]*container.ContainerMeta // /host/var/lib/docker/xyz/merged -> container
	rt                container.Runtime
	excludeNamespace  []string
	fileQueue         *util.Queue // files to scan
	savClient         *avira.SavClient
	alerter           *Alert                    // for sending msg to event center
	pri               *nodeinfo.PodResInfo      // pod info interface
	npw               *nodeinfo.NodePodsWatcher // node info
	cim               *k8s.ClusterInfoManager   // get cluster info
	maxUserWatches    int64
	concurrentScanNum int64
}

type WatchStats struct {
	WatchErrCnt int64
	WatchOkCnt  int64
}

type ContainerFile struct {
	container.ContainerMeta
	filenameInHost      string // full file path in container mount path.e.g./host/var/lib/docker/xyz/merged/home/xxx
	filenameInContainer string // /home/xxx
}

func (c *ContainerFile) CopyFrom(meta container.ContainerMeta) {
	c.ID = meta.ID
	c.Name = meta.Name
	c.State = meta.State
	c.ProcessID = meta.ProcessID
	c.PodUID = meta.PodUID
}

func (rs *RuntimeScanner) recordContainer(rootPath string, meta *container.ContainerMeta) {
	rs.Lock()
	defer rs.Unlock()
	rs.containerRootPath[rootPath] = meta
}

func (rs *RuntimeScanner) removeContainerPath(rootPath string) {
	rs.Lock()
	defer rs.Unlock()
	delete(rs.containerRootPath, rootPath)
}

func (rs *RuntimeScanner) shouldExcludeWatch(meta container.ContainerMeta) bool {
	return slices.Contains(rs.excludeNamespace, meta.PodNamespace())
}

func (rs *RuntimeScanner) shouldWatchByImageName(meta container.ContainerMeta) bool {
	value := os.Getenv(ImageScopeEnv)
	if len(value) == 0 {
		return true
	}
	for _, v := range meta.ImageRepoTags {
		if strings.Contains(v, value) {
			return true
		}
	}
	return false
}

func (rs *RuntimeScanner) removeWatchContainers(containers []container.ContainerMeta) error {
	var retErr error
	for _, meta := range containers {
		// check if in exclude names
		if rs.shouldExcludeWatch(meta) {
			logging.Get().Debug().Str("container", meta.Name).Msg("killed container in exclude ns,ignore removing watch")
			continue
		}
		if !rs.shouldWatchByImageName(meta) {
			logging.Get().Debug().Str("container", meta.Name).Msg("killed container not match image rule,ignore removing watch")
			continue
		}

		rootPath, ok := meta.GraphDriver.Data["MergedDir"]
		if !ok {
			logging.Get().Error().Str("container", meta.Name).Msg("container graph driver err")
			retErr = multierror.Append(retErr, fmt.Errorf("container graph driver err"))
			continue
		}
		// monitor path in docker.e.g./host/var/lib/docker/xxx/...
		monitorPath := filepath.Join("/host", rootPath)

		// not need to remove watch. inotify will auto remove container storage path when container stopped

		// remove container path
		rs.removeContainerPath(monitorPath)
	}

	return retErr
}

func (rs *RuntimeScanner) watchContainers(containers []container.ContainerMeta) error {
	var retErr error
	for k, meta := range containers {
		// check if in exclude names
		if rs.shouldExcludeWatch(meta) {
			logging.Get().Info().Str("container", meta.Name).Msg("exclude watch by ns")
			continue
		}

		if !rs.shouldWatchByImageName(meta) {
			logging.Get().Info().Str("container", meta.Name).Msg("exclude watch by image name rule")
			continue
		}

		// check root path
		rootPath, ok := meta.GraphDriver.Data["MergedDir"]
		if !ok {
			logging.Get().Error().Str("container", meta.Name).Msg("container graph driver err")
			retErr = multierror.Append(retErr, fmt.Errorf("container graph driver err"))
			continue
		}

		// monitor path in docker.e.g./host/var/lib/docker/xxx/...
		monitorPath := filepath.Join("/host", rootPath)
		rs.recordContainer(monitorPath, &containers[k])

		// add root path and subdirectory to monitor
		logging.Get().Info().Str("container", meta.Name).Str("monitorPath", monitorPath).Msg("start add watch")
		if err := rs.AddWatchDir(monitorPath); err != nil {
			logging.Get().Err(err).Str("container", meta.Name).Msg("failed to add monitor path")
			retErr = multierror.Append(retErr, err)
			continue
		}
		logging.Get().Info().Str("container", meta.Name).Str("monitorPath", monitorPath).Msg("add watch ok")
	}
	return retErr
}

func (rs *RuntimeScanner) watchExistContainers() error {
	containers, err := rs.rt.ListRunningContainers()
	if err != nil {
		logging.Get().Err(err).Msg("failed to list all containers")
		return err
	}

	metas := make([]container.ContainerMeta, 0)
	for _, v := range containers {
		meta, err := rs.rt.GetContainerMeta(v.ID)
		if err != nil && !errors.Is(err, container.ErrNotFoundPodID) {
			logging.Get().Err(err).Interface("container", v.Names).Msg("failed to get container meta")
			continue
		}
		metas = append(metas, meta)
	}

	return rs.watchContainers(metas)
}

func (rs *RuntimeScanner) runtimeEventCallback(message *container.EventMessage) {
	// a little check
	if message == nil {
		logging.Get().Error().Msg("recv nil runtime message")
		return
	}

	logging.Get().Debug().Str("container", message.ContainerInfo.Name).Str("event", message.Event).Msg("recv runtime event")
	if message.Event == "start" {
		go func(msg *container.EventMessage) {
			defer func() {
				if r := recover(); r != nil {
					logging.Get().Error().Msgf("handle start msg panic: %v.stack:%s", r, debug.Stack())
				}
			}()
			if err := rs.watchContainers([]container.ContainerMeta{msg.ContainerInfo}); err != nil {
				logging.Get().Err(err).Str("container", msg.ContainerInfo.Name).Msg("failed to watch")
			} else {
				logging.Get().Info().Str("container", msg.ContainerInfo.Name).Msg("watch end")
			}
		}(message)
	} else if message.Event == "kill" {
		// remove watch
		go func(msg *container.EventMessage) {
			defer func() {
				if r := recover(); r != nil {
					logging.Get().Error().Msgf("handle kill msg panic: %v.stack:%s", r, debug.Stack())
				}
			}()
			if err := rs.removeWatchContainers([]container.ContainerMeta{msg.ContainerInfo}); err != nil {
				logging.Get().Err(err).Str("container", msg.ContainerInfo.Name).Msg("failed to remove watch")
			} else {
				logging.Get().Info().Str("container", msg.ContainerInfo.Name).Msg("remove watch ok")
			}
		}(message)

	}
}

// connectSavServer block until connect ok
func (rs *RuntimeScanner) connectSavServer() error {
	stopChan := make(chan struct{})
	err := wait.PollUntil(20*time.Second,
		func() (done bool, err error) {
			// create avira client and connect to server
			scli, err := avira.NewSavClient(fmt.Sprintf("tcp:127.0.0.1:%d", avira.DefaultSavApiListenAddr))
			if err != nil {
				logging.Get().Err(err).Msg("failed to create sav clint")
				return false, nil
			}
			rs.savClient = scli
			close(stopChan)
			return true, nil
		}, stopChan)
	if err != nil {
		logging.Get().Err(err).Msg("failed to create sav client")
	} else {
		logging.Get().Info().Msg("create sav client ok")
	}
	return err
}

func (rs *RuntimeScanner) Run() error {
	// config inotify
	_ = rs.configInotifyMaxUserWatches()

	// list all container and add root path to watcher
	_ = rs.watchExistContainers()
	logging.Get().Info().Int64("watchErrCnt", rs.stats.WatchErrCnt).Int64("watchOkCnt", rs.stats.WatchOkCnt).Msg("after watch exist containers")

	wg := sync.WaitGroup{}

	// start avira daemon
	wg.Add(1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("panic : %v. stack: %s", r, debug.Stack())
			}
		}()
		defer wg.Done()
		savServer := avira.NewSavServer()
		savServer.StartServer()
		logging.Get().Info().Msg("start avira server succeed")
	}()
	// wait until sav client connect ok
	_ = rs.connectSavServer()

	// monitor runtime event
	wg.Add(1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("panic : %v. stack: %s", r, debug.Stack())
			}
		}()
		defer wg.Done()
		logging.Get().Info().Msg("runtime scanner start monitoring runtime event")
		err := rs.rt.MonitorEvent(rs.runtimeEventCallback)
		if err != nil {
			logging.Get().Err(err).Msg("failed to monitor runtime event")
		}
	}()

	// handle inotify event
	wg.Add(1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("panic : %v. stack: %s", r, debug.Stack())
			}
		}()
		defer wg.Done()
		logging.Get().Info().Msg("runtime scanner start handling inotify event")
		_ = rs.handleInotifyEvent()
	}()

	// scan file in queue
	rs.ScanFile()

	wg.Wait()
	logging.Get().Error().Msg("runtime scanner exit")

	return nil
}

func (rs *RuntimeScanner) ContainerByInotifyFile(filename string) (*container.ContainerMeta, string) {
	rs.Lock()
	defer rs.Unlock()
	for k, v := range rs.containerRootPath {
		if strings.HasPrefix(filename, k) {
			// k means container storage top path.e.g./host/var/lib/docker/xxx/merged
			logging.Get().Debug().Str("container", v.Name).Str("rootPath", k).Str("file", filename).Msg("found container by filename")
			return v, k
		}
	}
	return nil, ""
}

func (rs *RuntimeScanner) handleInotifyEvent() error {
	defer func() {
		rs.Lock()
		err := rs.watcher.Close()
		if err != nil {
			logging.Get().Err(err).Msg("failed to close watcher")
		}
		rs.Unlock()
	}()

	// Start listening for events.
	for {
		select {
		case event := <-rs.watcher.Event:
			filename := event.Name

			if event.Mask&inotify.InCloseWrite == inotify.InCloseWrite {
				// create a new file may contain one open,one create,multi modifies,one close-write
				// we only handle close-write event
				logging.Get().Debug().Str("file", filename).Msg("close write,add to queue")
				cf := ContainerFile{filenameInHost: filename}
				c, containerTopPath := rs.ContainerByInotifyFile(filename)
				if c == nil {
					logging.Get().Error().Interface("event", event).Msg("not found container by this file")
				} else {
					cf.CopyFrom(*c)
					logging.Get().Debug().Interface("event", event).Str("container", c.Name).Msg("recv event")
				}

				// record filepath in container for alert
				cf.filenameInContainer = strings.TrimPrefix(filename, containerTopPath)

				rs.fileQueue.Add(cf)
			} else if event.Mask&inotify.InCreate == inotify.InCreate {
				logging.Get().Debug().Str("file", event.Name).Msg("create")
				if utils.IsDir(filename) {
					if err := rs.AddWatchDir(filename); err != nil {
						logging.Get().Err(err).Str("dir", filename).Msg("failed to add watch")
					} else {
						logging.Get().Info().Str("dir", filename).Msg("add watch ok")
					}
				}
			} else if event.Mask&inotify.InOpen == inotify.InOpen {
				logging.Get().Debug().Str("file", filename).Msg("open")
			} else if event.Mask&inotify.InModify == inotify.InModify {
				logging.Get().Debug().Str("file", filename).Msg("modify")
			} else if event.Mask&inotify.InDelete == inotify.InDelete {
				logging.Get().Debug().Str("file", filename).Msg("delete")
			} else if event.Mask&inotify.InIgnored == inotify.InIgnored {
				// when container deleted,all storage path will be deleted,and watches will be auto removed too.
				// auto remove or manual remove some directory will generate ignore event.
				// the inode of the removed directory will become invalid, we need to remove this from inotify instance
				logging.Get().Debug().Str("file", filename).Msg("ignore")
				rs.Lock()
				if err := rs.watcher.RemoveWatch(filename); err != nil {
					logging.Get().Err(err).Str("file", filename).Msg("failed to remove watch")
				} else {
					logging.Get().Debug().Str("file", filename).Msg("remove watch ok")
				}
				rs.Unlock()
			} else if event.Mask&inotify.InUnmount == inotify.InUnmount {
				// rm container would trigger unmount
				logging.Get().Debug().Str("file", filename).Msg("unmount")
			}
		case err := <-rs.watcher.Error:
			logging.Get().Err(err).Msgf("watcher error")
		}
	}
}

func (rs *RuntimeScanner) AddWatchDir(rootPath string) error {
	err2 := filepath.WalkDir(filepath.Join(rootPath, "/"),
		func(path string, dirEntry os.DirEntry, err error) error {
			if err != nil {
				// just log.but return nil to continue
				logging.Get().Err(err).Msg("walk dir err")
				return nil
			}
			if dirEntry.IsDir() {
				rs.Lock()
				if err := rs.watcher.AddWatch(path, inotify.InCloseWrite|inotify.InCreate); err != nil {
					rs.stats.WatchErrCnt++
					logging.Get().Err(err).Str("path", path).Msg("failed to add dir to watch list")
				} else {
					rs.stats.WatchOkCnt++
				}
				rs.Unlock()
			}
			return nil
		})

	if err2 != nil {
		logging.Get().Err(err2).Msg("failed to add all subdirectories")
		return err2
	}

	return nil
}

func (rs *RuntimeScanner) configInotifyMaxUserWatches() error {
	param := fmt.Sprintf("fs.inotify.max_user_watches=%d", rs.maxUserWatches)
	cmd := exec.Command("sysctl", param)
	err := cmd.Run()
	if err != nil {
		logging.Get().Warn().Str("msg", err.Error()).Str("maxWatches", param).Msg("failed to change fs.inotify.max_user_watches, may not watch many directory")
		return err
	}
	logging.Get().Info().Str("maxWatches", param).Msg("config fs.inotify.max_user_watches ok")
	return nil
}

func (rs *RuntimeScanner) fillK8sPodInfo(podID string, ev *EventArg) error {
	// pod info
	ev.PodUID = podID

	// k8s pod info
	podInfo, err := rs.npw.GetPodByUID(podID)
	if err != nil {
		logging.Get().Err(err).Msg("failed to get pod info")
		return err
	}
	ev.PodName = podInfo.Name
	ev.Namespace = podInfo.Namespace

	// k8s resource info
	resource, ok := rs.pri.GetPod(podInfo.Namespace, podInfo.Name)
	if !ok {
		logging.Get().Error().Str("podName", podInfo.Name).Msg("failed to get pod resource")
		return fmt.Errorf("failed to get pod resource")
	}
	ev.ResourceKind = resource.Kind
	ev.ResourceName = resource.Name

	return nil
}

func (rs *RuntimeScanner) sendAlert(malware []avira.Malware, cf ContainerFile) error {
	malwareNames := make([]string, 0)
	for _, v := range malware {
		malwareNames = append(malwareNames, v.Name)
	}

	// get cluster key.不管是不是k8s容器，我们现在都需要clusterKey
	clusterKey, ok := rs.cim.ClusterKey()
	if !ok {
		logging.Get().Error().Msg("failed to get cluster key")
		return fmt.Errorf("failed to get cluster key")
	}
	clusterName, ok := rs.cim.ClusterName()
	if !ok {
		logging.Get().Error().Msg("failed to get cluster name")
		return fmt.Errorf("failed to get cluster name")
	}

	// basic info
	ev := &EventArg{
		FilePath:      cf.filenameInContainer,
		ContainerID:   cf.ID,
		ContainerName: cf.Name,
		Hostname:      rs.npw.NodeName,
		ClusterID:     clusterKey,
		Cluster:       clusterName,
		Malware:       malwareNames,
	}
	if len(cf.PodUID) == 0 {
		logging.Get().Debug().Msg("raw container")
		// raw container
		return rs.alerter.Send(ev)
	}

	// for k8s
	if err := rs.fillK8sPodInfo(cf.PodUID, ev); err != nil {
		logging.Get().Err(err).Msg("failed to fill pod info to event")
		return err
	}

	return rs.alerter.Send(ev)
}

func (rs *RuntimeScanner) ScanFile() {

	logging.Get().Debug().Int64("concurrentScanNum", rs.concurrentScanNum).Msg("read to scan file")

	limit := semaphore.NewWeighted(rs.concurrentScanNum)

	rs.fileQueue.Consume(func(item interface{}) {
		if err := limit.Acquire(context.Background(), 1); err != nil {
			logging.Get().Err(err).Msg("failed to acquire semaphore")
			return
		}

		go func() {
			defer func() {
				if r := recover(); r != nil {
					logging.Get().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
				}
			}()
			defer limit.Release(1)

			switch typed := item.(type) {
			case ContainerFile:
				cf := item.(ContainerFile)

				infoLog := func() *zerolog.Event {
					return logging.Get().Info().Str("container", cf.Name).Str("file", cf.filenameInHost)
				}
				errLog := func(err error) *zerolog.Event {
					return logging.Get().Err(err).Str("container", cf.Name).Str("file", cf.filenameInHost)
				}

				// create tmp sav client
				scli, err := avira.NewSavClient(fmt.Sprintf("tcp:127.0.0.1:%d", avira.DefaultSavApiListenAddr))
				if err != nil {
					errLog(err).Msg("failed to create sav clint")
					return
				}
				defer func() {
					if err := scli.Close(); err != nil {
						errLog(err).Msg("failed to close sav client")
					}
				}()

				// scan file
				res, err := scli.ScanFile(cf.filenameInHost)
				if err != nil {
					errLog(err).Msg("failed to scan")
					return
				}

				// send msg
				if len(res) > 0 {
					infoLog().Int("malwareCnt", len(res)).Msg("found malware")
					if err := rs.sendAlert(res, cf); err != nil {
						errLog(err).Msg("failed to send to event center")
					} else {
						infoLog().Msg("send to event center ok")
					}
				} else {
					infoLog().Msg("scan ok,not found malware")
				}

			default:
				logging.Get().Error().Msgf("file queue element type err.%v", typed)
			}
		}()

	})
}

func NewRuntimeScanner(opts ...OptionFunc) (*RuntimeScanner, error) {
	r := &RuntimeScanner{
		containerRootPath: make(map[string]*container.ContainerMeta),
		fileQueue:         util.NewQueue(),
		maxUserWatches:    DefaultMaxUserWatches,
		concurrentScanNum: DefaultConcurrentScanNum,
	}

	for _, option := range opts {
		option(r)
	}

	// exclude namespace
	r.excludeNamespace = global.GetExcludeNamespaces()

	// runtime interface
	rt, err := container.CreateRuntimeCli()
	if err != nil {
		logging.Get().Err(err).Msg("failed to create runtime interface")
		return nil, err
	}
	r.rt = rt

	// alerter
	a, err := NewAlert()
	if err != nil {
		logging.Get().Err(err).Msg("failed to create alerter")
		return nil, err
	}
	r.alerter = a

	// create watcher at last
	w, err := inotify.NewWatcher()
	if err != nil {
		logging.Get().Err(err).Msg("failed to create fs watcher")
		return nil, err
	}
	r.watcher = w

	return r, nil
}
