package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/k8s"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

func main() {
	var bathSize int
	var bathInterval int
	var pushInterval int
	flag.IntVar(&bathSize, "batchSize", 10, "batch size")
	flag.IntVar(&bathInterval, "batchInterval", 1, "batch interval,default:1(minute)")
	flag.IntVar(&pushInterval, "pushInterval", 10, "push interval,default:10(minute)")
	flag.Parse()

	if bathSize < 1 {
		bathSize = 1
	}
	if bathInterval < 1 {
		bathInterval = 1
	}
	if pushInterval < 10 {
		pushInterval = 10
	}

	ticker := time.NewTicker(time.Minute * time.Duration(pushInterval))

	for {
		if err := worker(bathSize, bathInterval); err != nil {
			logging.GetLogger().Error().Err(err).Msg("safe-node push node image failure")
		}
		ticker.Reset(time.Minute * time.Duration(pushInterval))
		<-ticker.C
	}
}

func worker(bathSize, bathInterval int) error {
	clusterManagerURL := os.Getenv("CLUSTER-MANAGER-ADDR")
	nameSpace := os.Getenv("MY_POD_NAMESPACE")
	if strings.Contains(nameSpace, ":") {
		nameSpace = strings.Replace(nameSpace, ":", consts.ColonSalt, 01)
	}

	if clusterManagerURL == "" || nameSpace == "" {
		return fmt.Errorf("clusterManager or nameSpace is empty %s,%s ", clusterManagerURL, nameSpace)
	}
	logging.GetLogger().Info().Msgf("clusterManager:%s,namespace:%s", clusterManagerURL, nameSpace)

	preImages, err := getImages()
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("safe-node getImages")
		return err
	}

	podName, err := os.Hostname()
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("safe-node Hostname")
		return err
	}
	nodeos := runtime.GOOS

	url := os.Getenv("SAFENODE-BUF-REGISTRY-URL")
	username := os.Getenv("SAFENODE-BUF-REGISTRY-USER")
	password := os.Getenv("SAFENODE-BUF-REGISTRY-PASSWORD")
	if url == "" || username == "" || password == "" || nameSpace == "" {
		logging.GetLogger().Info().Msg("safe-node url or username or password is empty")
		return fmt.Errorf("url or username or password is empty")
	}

	manager := k8s.NewClusterInfoManager(clusterManagerURL)
	key, b := manager.ClusterKey()
	if !b || key == "" {
		logging.GetLogger().Info().Msg("safe-node not fond the cluster key")
		return fmt.Errorf("not fond the cluster key")
	}

	if err := login(url, username, password); err != nil {
		logging.GetLogger().Error().Err(err).Msg("safe-node login")
		return err
	}

	for i := range preImages {
		pre, err := getPreImage(preImages[i])
		if err != nil {
			logging.GetLogger().Error().Err(err).Msg("safe-node getPreImage")
			continue
		}
		info := NodeImageInfo{
			PodName:    podName,
			Namespace:  nameSpace,
			ClasterKey: key,
			Os:         nodeos,
			Lib:        url,
			ImageName:  pre,
		}

		after := changeTage(info)
		if err := reTage(preImages[i], after); err != nil {
			logging.GetLogger().Error().Err(err).Msgf("safe-node reTage:pre:%s after:%s", preImages[i], after)
			continue
		}
		if err := pushImage(after); err != nil {
			logging.GetLogger().Error().Err(err).Msgf("safe-node pushImage imageName:%s", after)
		}
		if err := rmImage(after); err != nil {
			logging.GetLogger().Error().Err(err).Msgf("safe-node rmImage:imageName:%s", after)
		}
		// 传了10个就停一份钟
		if i%bathSize == 0 {
			time.Sleep(time.Duration(bathInterval) * time.Minute)
		}
	}
	return nil
}

func getPreImage(imge string) (string, error) {

	var nameOpts []name.Option
	nameOpts = append(nameOpts, name.Insecure)

	ref, err := name.ParseReference(imge, nameOpts...)
	if err != nil {
		return "", err
	}

	repo := ref.Context()

	registryStr := repo.RegistryStr()

	tag := ref.Identifier()
	repositoryName := ref.Context().RepositoryStr()

	if strings.Contains(registryStr, ":") {
		registryStr = strings.Replace(registryStr, ":", consts.ColonSalt, -1)
	}

	return registryStr + "/" + repositoryName + ":" + tag, nil
}

func changeTage(info NodeImageInfo) string {
	// 仓库地址/tensorsec/clusterKey/namespace/podName/podIp/os/镜像名
	image := fmt.Sprintf(consts.NodeSafeTage, getLib(info.Lib), info.ClasterKey, info.Namespace, info.PodName, info.Os, info.ImageName)
	return image
}

type NodeImageInfo struct {
	PodName    string
	Namespace  string
	ClasterKey string
	Os         string
	Lib        string
	ImageName  string
}

func reTage(pre, after string) error {
	osCmd := exec.Command("docker", "tag", pre, after)
	var stdout, stderr bytes.Buffer
	osCmd.Stdout = &stdout // 标准输出
	osCmd.Stderr = &stderr // 标准错误
	err := osCmd.Run()
	if err != nil {
		logging.GetLogger().Info().Msgf("safe-node docker args:%v", osCmd.Args)
		logging.GetLogger().Info().Msgf("safe-node docker err:%s", stderr.String())
		logging.GetLogger().Error().Err(err).Msgf("safe-node docker retag pre:%s,after:%s", pre, after)
		return err
	}
	logging.GetLogger().Debug().Msgf("safe-node docker retag:%s", stdout.String())
	return nil
}

func getNodIp() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}

	for _, address := range addrs {
		// 检查ip地址判断是否回环地址
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String(), nil
			}
		}
	}
	return "", errors.New("can not find node ip")
}

func getImages() ([]string, error) {
	osCmd := exec.Command("docker", "images", "-a")

	stdout, err := osCmd.CombinedOutput()
	if err != nil {
		logging.GetLogger().Error().Err(err).Msgf("safe-node docker StdoutPipe:%v ", osCmd.Args)
		return nil, err
	}

	imgs := strings.Split(string(stdout), "\n")

	// 处理数据
	images := make([]string, 0)
	if len(imgs) <= 1 {
		return images, nil
	}

	for i := 1; i < len(imgs); i++ {
		ss := strings.Split(imgs[i], " ")
		ss1 := make([]string, 0)
		for j := range ss {
			if strings.Trim(ss[j], " ") != "" {
				ss1 = append(ss1, strings.Trim(ss[j], " "))
			}
			if len(ss1) >= 2 && ss1[0] != "<none>" && ss1[1] != "<none>" {
				images = append(images, ss1[0]+":"+ss1[1])
				break
			}
		}
	}
	logging.GetLogger().Info().Msgf("safe-node docker images getting image:%d", len(imgs))
	return images, nil
}

func login(url, username, password string) error {
	osCmd := exec.Command("docker", "login", "-u", username, "-p", password, getLib(url))
	logging.GetLogger().Debug().Msgf("safe-node login success %v", osCmd.Args)

	err := osCmd.Run()
	if err != nil {
		logging.GetLogger().Error().Err(err).Msgf("safe-node login failed:%v", osCmd.Args)
		return err
	}
	logging.GetLogger().Debug().Msg("safe-node login successful")
	return nil
}

func pushImage(image string) error {

	osCmd := exec.Command("docker", "push", image)
	err := osCmd.Run()
	if err != nil {
		logging.GetLogger().Error().Err(err).Msgf("safe-node docker push :%s", image)
		return err
	}
	logging.GetLogger().Info().Msgf("safe-node docker push successful :%s", image)
	return nil
}

func rmImage(imageName string) error {
	osCmd := exec.Command("docker", "rmi", "-f", imageName)

	err := osCmd.Run()
	if err != nil {
		logging.GetLogger().Error().Err(err).Msgf("safe-node docker delete image：%s:%v", imageName, osCmd.Args)
		return err
	}
	logging.GetLogger().Info().Msgf("safe-node docker delete image：%s", imageName)

	return nil
}

func getLib(url string) string {
	lib := strings.Replace(url, "http://", "", -1)
	lib = strings.Replace(lib, "https://", "", -1)

	return lib
}
