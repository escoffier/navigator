package utils

//import (
//	"context"
//	"os"
//	"path/filepath"
//	"reflect"
//	"strconv"
//	"sync"
//	"time"
//
//	dockerType "github.com/docker/docker/api/types"
//	dockerClient "github.com/docker/docker/client"
//	log "github.com/sirupsen/logrus"
//)
//
//func listDockerContainerId(ctx context.Context, docker dockerClient.APIClient) ([]string, error) {
//	containers, err := docker.ContainerList(ctx, dockerType.ContainerListOptions{})
//	if err != nil {
//		return []string{}, err
//	}
//	var result []string
//	for _, c := range containers {
//		result = append(result, c.ID)
//	}
//	return result, nil
//}
//
//func getNsByPid(pid int) (uint32, error) {
//	nsStr, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "ns", "pid"))
//	if err != nil {
//		return 0, err
//	}
//	nsV, err := strconv.ParseUint(nsStr[5:len(nsStr)-1], 10, 0)
//
//	return uint32(nsV), err
//}
//
//func listDockerContainerInfo(ctx context.Context, docker dockerClient.APIClient, containerIds []string) (NsMapT, error) {
//	result := make(NsMapT, len(containerIds))
//	ns, err := getNsByPid(1)
//	if err != nil {
//		return result, err
//	}
//	result[ns] = ContainerInfo{
//		Id:    "0000000000000000000000000000000000000000000000000000000000000000",
//		Image: "host:host",
//		Name:  "host",
//	}
//	for _, containerId := range containerIds {
//		inspectInfo, err := docker.ContainerInspect(ctx, containerId)
//		if err != nil {
//			return result, err
//		}
//		if inspectInfo.State.Status == "running" {
//			ns, err := getNsByPid(inspectInfo.State.Pid)
//			if err != nil {
//				return result, err
//			}
//			result[ns] = ContainerInfo{
//				Id:    inspectInfo.ID,
//				Image: inspectInfo.Config.Image,
//				Name:  inspectInfo.Name[1:],
//			}
//		}
//	}
//	return result, nil
//}
//
//func NewNsMap() *NsMap {
//	return &NsMap{
//		Lock: sync.RWMutex{},
//		Data: make(NsMapT, 0),
//	}
//}
//
//func (nsMap *NsMap) RefreshNsMap() error {
//	containerIds, err := listDockerContainerId(ctx, docker)
//	if err != nil {
//		return err
//	}
//	data, err := listDockerContainerInfo(ctx, docker, containerIds)
//	if err != nil {
//		return err
//	}
//	nsMap.Lock.Lock()
//	if len(data) > len(nsMap.Data) {
//		nsMap.Data = make(NsMapT, len(data))
//	}
//	nsMap.Data = data
//	nsMap.Lock.Unlock()
//	return nil
//}
//
//func (nsMap *NsMap) RefreshNsMapBackground(d time.Duration) {
//	for {
//		containerIds, err := listDockerContainerId(ctx, docker)
//		if err != nil {
//			log.Fatalf("Cannot list container ID: %v", err)
//		}
//		data, err := listDockerContainerInfo(ctx, docker, containerIds)
//		if err != nil {
//			log.Fatalf("Cannot list container inspect information: %v", err)
//		}
//		if !reflect.DeepEqual(data, nsMap.Data) {
//			nsMap.Lock.Lock()
//			nsMap.Data = data
//			nsMap.Lock.Unlock()
//		}
//		time.Sleep(d)
//	}
//}
