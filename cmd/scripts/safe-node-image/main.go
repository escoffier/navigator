package main

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

func main() {

	inter := os.Getenv("SAFENODE-BUF-INTERNA")
	inter1, err := strconv.ParseInt(inter, 10, 64)
	if err != nil {
		inter1 = 20
	}

	ticker := time.NewTicker(time.Minute * time.Duration(inter1))

	for {
		if err := worker(); err != nil {
			logging.GetLogger().Error().Err(err).Msg("safe-node pull node image failure")
			continue
		}
		ticker.Reset(time.Minute * time.Duration(inter1))
		<-ticker.C
	}
}

func worker() error {
	preImages, err := getImages()
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("safe-node getImages")
		return err
	}
	ip, err := getNodIp()
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("safe-node getNodIp")
		return err
	}
	hostname, err := os.Hostname()
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("safe-node Hostname")
		return err
	}
	nodeos := runtime.GOOS

	url := os.Getenv("SAFENODE-BUF-REGISTRY-URL")
	username := os.Getenv("SAFENODE-BUF-REGISTRY-USER")
	password := os.Getenv("SAFENODE-BUF-REGISTRY-PASSWORD")

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

		after := changeTage(url, pre, hostname, ip, nodeos)
		if err := reTage(preImages[i], after); err != nil {
			logging.GetLogger().Error().Err(err).Msgf("safe-node reTage:pre:% after:%s", pre, after)
			continue
		}
		if err := pushImage(after); err != nil {
			logging.GetLogger().Error().Err(err).Msg("safe-node pushImage")
		}
		if err := rmImage(after); err != nil {
			logging.GetLogger().Error().Err(err).Msg("safe-node rmImage")
		}
		// 传了10个就停一份钟
		if i%10 == 0 {
			time.Sleep(time.Minute)
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

	return registryStr + "/" + repositoryName + ":" + tag, nil
}

func changeTage(lib, pre, hostname, ip, os string) string {
	return fmt.Sprintf(consts.NodeSafeTage, getLib(lib), hostname, ip, os, pre)
}

func reTage(pre, after string) error {
	osCmd := exec.Command("docker", "tag", pre, after)
	err := osCmd.Run()
	if err != nil {
		logging.GetLogger().Error().Err(err).Msgf("safe-node docker retag :%s", pre)
		return err
	}
	logging.GetLogger().Debug().Msgf("safe-node docker retag:%s", pre)
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

	stdout, err := osCmd.StdoutPipe()
	if err != nil {
		fmt.Println(err.Error())
		return nil, err
	}

	err = osCmd.Start()

	if err != nil {
		logging.GetLogger().Error().Err(err).Msgf("safe-node docker ps getting image:%v", osCmd.Args)
		return nil, err
	}
	logScan := bufio.NewScanner(stdout)

	imgs := make([]string, 0)
	for logScan.Scan() {
		imgs = append(imgs, logScan.Text())
	}
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
			if len(ss1) >= 2 {
				images = append(images, ss1[0]+":"+ss1[1])
				break
			}
		}
	}

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
