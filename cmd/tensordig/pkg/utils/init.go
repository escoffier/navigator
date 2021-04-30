package utils

import (
	"context"
	//"os"
	"strconv"
	"strings"
	"sync"

	"gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/constant"
	//dockerClient "github.com/docker/docker/client"
	log "github.com/sirupsen/logrus"
)

type ContainerInfo struct {
	Id    string
	Image string
	Name  string
}

type NsMapT map[uint32]ContainerInfo

type NsMap struct {
	Data NsMapT
	Lock sync.RWMutex
}

var ctx context.Context

//var docker dockerClient.APIClient

//func createDockerClient() (dockerClient.APIClient, error) {
//	docker_api_version := os.Getenv("DOCKER_API_VERSION")
//	if docker_api_version >= "1.38" {
//		os.Setenv("DOCKER_API_VERSION", "1.38")
//	}
//	docker, err := dockerClient.NewEnvClient()
//	if err != nil {
//		return nil, err
//	}
//	return docker, nil
//}

func init() {
	var err error
	ctx = context.Background()
	//docker, err = createDockerClient()
	if err != nil {
		log.Fatalf("Docker init error: %v", err)
	}
}

func Destory() {
	ctx.Done()
	//docker.Close()
}

func GetFieldsAbbr(syscall *string) map[string]string {
	key := *syscall + "_split"
	args := constant.SyscallIoStructMap[key]
	if len(args) == 0 {
		return nil
	}
	var result = make(map[string]string, len(args))
	for _, field := range strings.Split(args, " ") {
		detail := strings.Split(field, ":")
		fieldName := detail[0]
		fieldType := detail[1]
		result[fieldName] = fieldType
	}
	return result
}

func InttoIP4(ipInt int64) string {
	// need to do two bit shifting and “0xff” masking
	b0 := strconv.FormatInt((ipInt>>24)&0xff, 10)
	b1 := strconv.FormatInt((ipInt>>16)&0xff, 10)
	b2 := strconv.FormatInt((ipInt>>8)&0xff, 10)
	b3 := strconv.FormatInt((ipInt & 0xff), 10)
	return b3 + "." + b2 + "." + b1 + "." + b0
}

func IP4ToInt(ip string) uint32 {
	var result uint32
	splits := strings.Split(ip, ".")
	for i, s := range splits {
		v, err := strconv.ParseUint(s, 10, 8)
		if err != nil {
			log.Error("Parse ip error")
		}
		result = result | (uint32(v) << (8 * uint32(i)))
	}
	return result
}

func CBytesToGoString(data []byte) string {
	var s strings.Builder
	for _, v := range data {
		if v > 0 {
			s.WriteByte(v)
		} else {
			break
		}
	}
	return s.String()
}
