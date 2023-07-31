package cis

import (
	"context"
	"fmt"
	"runtime/debug"
	"strings"
	"sync"

	"gitlab.com/piccolo_su/vegeta/cmd/daemon/cis/checker"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/cis/pkg/check"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/container"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/nodeinfo"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"

	_ "gitlab.com/piccolo_su/vegeta/cmd/daemon/cis/checker/nginx"
	_ "gitlab.com/piccolo_su/vegeta/cmd/daemon/cis/checker/postgres"
	_ "gitlab.com/piccolo_su/vegeta/cmd/daemon/cis/checker/redis"
	_ "gitlab.com/piccolo_su/vegeta/cmd/daemon/cis/checker/ssh"
)

var (
	containerPathTemplate = "/host/proc/%d/root"
)

type CisController struct {
	rt       container.Runtime
	checkers map[string]checker.CheckerService
	alerter  *Alert                    // for sending msg to event center
	pri      *nodeinfo.PodResInfo      // pod info interface
	npw      *nodeinfo.NodePodsWatcher // node info
	cim      *k8s.ClusterInfoManager   // get cluster info
}

func NewCisController(opts ...OptionFunc) (*CisController, error) {

	rt, err := container.CreateRuntimeCli()
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("create runtime cli fail")
		return nil, err
	}

	checkers := make(map[string]checker.CheckerService)

	cController := &CisController{
		rt:       rt,
		checkers: checkers,
	}

	a, err := NewAlert()
	if err != nil {
		logging.GetLogger().Err(err).Msg("failed to create alerter")
		return nil, err
	}
	cController.alerter = a

	for _, opt := range opts {
		opt(cController)
	}

	return cController, nil

}

func (c *CisController) Start(ctx context.Context) error {
	logging.GetLogger().Info().Msg("cis checker start")

	// get running containers path
	runningContainers, err := c.getRunningContainers()
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("get running containers path fail")
		return err
	}

	// load config
	cs := checker.GetServices()
	for k := range cs {

		config := checker.CheckerServiceConfig{
			Type: k,
		}
		srv, err := checker.Open(config)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("new checker service fail")
			continue
		}
		c.checkers[k] = srv
	}

	for _, srv := range c.checkers {
		switch srv.CheckerType() {
		case "host":
			control, err := srv.RunChecks(context.Background(), "/host")
			if err != nil {
				logging.GetLogger().Error().Err(err).Msg("run checks fail")
				continue
			}
			c.sendAlert(control.(*check.Controls), container.ContainerMeta{}, srv.Name())
		case "container":
			for _, rc := range runningContainers {
				containerPath := fmt.Sprintf(containerPathTemplate, rc.ProcessID)
				control, err := srv.RunChecks(context.Background(), containerPath)
				if err != nil {
					if !strings.Contains(err.Error(), "no config file found") {
						logging.GetLogger().Err(err).Msg("run checks fail")
					} else {
						logging.GetLogger().Warn().Msgf("container %s has no config file", rc.Name)
					}
					continue
				}
				c.sendAlert(control.(*check.Controls), rc, srv.Name())
			}
		default:
			logging.GetLogger().Error().Msgf("unknown checker type: %s", srv.CheckerType())
		}
	}

	var wg sync.WaitGroup
	// monitor runtime event
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Msgf("Panic: %v. stack: %s", r, debug.Stack())
			}
		}()
		logging.GetLogger().Info().Msg("runtime scanner start monitoring runtime event")
		err := c.rt.MonitorEvent(c.runtimeEventCallback)
		if err != nil {
			logging.GetLogger().Err(err).Msg("failed to monitor runtime event")
		}
	}()

	wg.Wait()

	return nil
}

func (c *CisController) runtimeEventCallback(message *container.EventMessage) {
	if message == nil {
		logging.GetLogger().Error().Msg("event message is nil")
		return
	}
	if message.Event == "start" {
		go func(msg *container.EventMessage) {
			defer func() {
				if r := recover(); r != nil {
					logging.GetLogger().Error().Msgf("Panic: %v. stack: %s", r, debug.Stack())
				}

			}()
			containerPath := fmt.Sprintf(containerPathTemplate, msg.ContainerInfo.ProcessID)

			for _, srv := range c.checkers {
				if srv.CheckerType() == "container" {
					control, err := srv.RunChecks(context.Background(), containerPath)
					if err != nil {
						if !strings.Contains(err.Error(), "no config file found") {
							logging.GetLogger().Err(err).Msg("run checks fail")
						} else {
							logging.GetLogger().Warn().Msgf("container has no config file, containerPath %s, pid: %d", containerPath, msg.ContainerInfo.ProcessID)
						}
						continue
					}
					c.sendAlert(control.(*check.Controls), msg.ContainerInfo, srv.Name())
				}
			}
		}(message)
	}
}

func (c *CisController) getRunningContainers() ([]container.ContainerMeta, error) {

	var runningContainers []container.ContainerMeta

	containers, err := c.rt.ListRunningContainers()
	if err != nil {
		return nil, err
	}
	for _, container := range containers {
		logging.GetLogger().Info().Msgf("container: %v", container)
		cm, err := c.rt.GetContainerMeta(container.Namespace, container.ID)
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("get container meta fail")
			continue
		}
		runningContainers = append(runningContainers, cm)
	}
	return runningContainers, nil
}

func (cc *CisController) sendAlert(control *check.Controls, cm container.ContainerMeta, chckerName string) error {

	// get cluster key.不管是不是k8s容器，我们现在都需要clusterKey
	clusterKey, ok := cc.cim.ClusterKey()
	if !ok {
		logging.GetLogger().Error().Msg("failed to get cluster key")
		return fmt.Errorf("failed to get cluster key")
	}
	clusterName, ok := cc.cim.ClusterName()
	if !ok {
		logging.GetLogger().Error().Msg("failed to get cluster name")
		return fmt.Errorf("failed to get cluster name")
	}

	// basic info
	ev := &EventArg{
		ContainerID:   cm.ID,
		ContainerName: cm.Name,
		Hostname:      cc.npw.NodeName,
		ClusterID:     clusterKey,
		Cluster:       clusterName,
		Checker:       chckerName,
	}

	if len(cm.PodUID) == 0 {
		logging.GetLogger().Debug().Msg("raw container")
	}

	// for k8s
	if len(cm.PodUID) > 0 {
		if err := cc.fillK8sPodInfo(cm.PodUID, ev); err != nil {
			logging.GetLogger().Err(err).Msg("failed to fill pod info to event")
		}
	}
	// for host
	if len(cm.ID) == 0 {
		ev.ContainerID = "host"
		ev.ContainerName = "host"
		logging.GetLogger().Debug().Msg("host container")
	}

	for _, g := range control.Groups {
		for _, c := range g.Checks {

			if c.State == check.FAIL {
				ev.State = check.FAIL
				ev.Text = c.Text
				ev.RunCommand = c.Audit
				ev.CommandOutput = c.AuditOutput
				err := cc.alerter.Send(ev)
				if err != nil {
					logging.GetLogger().Err(err).Str("container meta: ", fmt.Sprintf("%v", cm)).
						Str("check: ", fmt.Sprintf("%v", c)).Msg("failed to send alert")
				}
			}
		}
	}

	return nil
}

func (rs *CisController) fillK8sPodInfo(podID string, ev *EventArg) error {
	// pod info
	ev.PodUID = podID

	// k8s pod info
	podInfo, err := rs.npw.GetPodByUID(podID)
	if err != nil {
		logging.GetLogger().Err(err).Msg("failed to get pod info")
		return err
	}
	ev.PodName = podInfo.Name
	ev.Namespace = podInfo.Namespace

	// k8s resource info
	resource, ok := rs.pri.GetPod(podInfo.Namespace, podInfo.Name)
	if !ok {
		logging.GetLogger().Error().Str("podName", podInfo.Name).Msg("failed to get pod resource")
		return fmt.Errorf("failed to get pod resource")
	}
	ev.ResourceKind = resource.Kind
	ev.ResourceName = resource.Name

	return nil
}
