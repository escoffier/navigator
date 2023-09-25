package nodeinfo

import (
	"bufio"
	"context"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/containerassets"
	"net/http"
	"net/url"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/containers/podman/v3/pkg/bindings"
	"github.com/containers/podman/v3/pkg/bindings/containers"
	"github.com/containers/podman/v3/pkg/domain/entities"
	json "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"gitlab.com/security-rd/go-pkg/logging"
)

var _ ContainerInfoManager = (*PodmanInfoManager)(nil)

type PodmanInfoManager struct {
	ctx           context.Context
	podmanCli     *bindings.Connection
	containerData map[string]int64 // map[containerId]time

	sync.RWMutex
}

func (p *PodmanInfoManager) SetPodStore(store containerassets.PodCache) {
}

func (p *PodmanInfoManager) RunCmd(ctx context.Context, containerId string, cmd []string) (resp string, err error) {
	//TODO implement me
	return "", errors.New("podman: implement me")
}

func (p *PodmanInfoManager) AddEventHandler(handler ContainerEventHandler) {
	//TODO implement me
	panic("implement me")
}

func NewPodmanInfoManager() (*PodmanInfoManager, error) {
	uri := os.Getenv("PODMAN_SOCKET_ADDR")
	if len(uri) == 0 {
		uri = "unix://run/podman/podman.sock"
	}

	ctx, err := bindings.NewConnection(context.Background(), uri)
	if err != nil {
		return nil, errors.Errorf("podman client failed, %v", err)
	}

	rs := &PodmanInfoManager{
		ctx:           ctx,
		containerData: make(map[string]int64, 30),
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
			}
		}()

		rs.clearContainerTimeoutData()
	}()

	return rs, nil
}

func (p *PodmanInfoManager) clearContainerTimeoutData() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	count := 0
	for now := range ticker.C {
		func(nowTime time.Time) {
			defer func() {
				if r := recover(); r != nil {
					logging.Get().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
				}
			}()

			p.Lock()
			defer p.Unlock()

			if count >= 60 { // if a map keeps a stable size but is with continouous add or delete, it should be reconstructed after a period of time to prevent memory leak
				newMap := make(map[string]int64, len(p.containerData))
				for containerID, timestamp := range p.containerData {
					if nowTime.Unix()-timestamp >= containerIDTimeoutSec {
						continue
					}
					newMap[containerID] = timestamp
				}
				p.containerData = newMap
				count = 0
			} else {
				for containerID, timestamp := range p.containerData {
					if nowTime.Unix()-timestamp < containerIDTimeoutSec {
						continue
					}
					delete(p.containerData, containerID)
				}
				count++
			}

		}(now)
	}
}

func (p *PodmanInfoManager) GetContainerPid(containerID string) (int, string, error) {
	containerID = strings.TrimPrefix(containerID, "cri-o://")
	data, err := containers.Inspect(p.ctx, containerID, nil)
	if err != nil {
		return 0, "", errors.Errorf("get container pid by inspect failed, %v", err)
	}

	return data.State.Pid, containerID, nil
}

func (p *PodmanInfoManager) ListenEvents(saveData SaveContainerDataFunc) {
	conn, err := bindings.GetClient(p.ctx)
	if err != nil {
		logging.Get().Err(err).Msg("podman get client failed")
		return
	}

	params := url.Values{"filters": []string{"{\"event\":[\"create\"]}"}}
	rsp, err := conn.DoRequest(nil, http.MethodGet, "/events", params, nil)
	if err != nil {
		logging.Get().Err(err).Msg("request podman events failed")
		return
	}

	defer rsp.Body.Close()

	for {
		reader := bufio.NewReader(rsp.Body)
		line, _, err := reader.ReadLine()
		if err != nil {
			logging.Get().Err(err).Msg("read podman events data failed")
			break
		}

		if http.StatusOK != rsp.StatusCode {
			logging.Get().Error().Msgf("podman event response error, status code : %v", rsp.StatusCode)
			break
		}

		ev := entities.Event{}
		err = json.Unmarshal(line, &ev)
		if err != nil {
			logging.Get().Err(err).Msg("json unmarsh podman event data failed")
			continue
		}

		saveData(ev.ID, ev.Time)
	}
}

func (p *PodmanInfoManager) Start() error {
	//docker events
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Get().Error().Msgf("Panic: %v. Stack: %s", r, debug.Stack())
			}
		}()
		//docker events
		p.ListenEvents(p.saveContainerData)
	}()

	return nil
}

func (p *PodmanInfoManager) saveContainerData(containerID string, timestamp int64) {
	defer func() {
		if r := recover(); r != nil {
			logging.Get().Error().Msgf("Panic: %v. stack: %s", r, debug.Stack())
		}
	}()

	if len(containerID) == 0 || timestamp <= 0 {
		return
	}

	containerID = strings.TrimPrefix(containerID, "cri-o://")
	if len(containerID) > 12 {
		containerID = containerID[0:12]
	}

	p.Lock()
	defer p.Unlock()
	p.containerData[containerID] = timestamp
}

func (p *PodmanInfoManager) FindContainerCacheData(containerID string) (int64, bool) {
	if len(containerID) == 0 {
		return 0, false
	}

	if len(containerID) > 12 {
		containerID = containerID[0:12]
	}

	p.RLock()
	defer p.RUnlock()
	timestamp, ok := p.containerData[containerID]
	return timestamp, ok
}
