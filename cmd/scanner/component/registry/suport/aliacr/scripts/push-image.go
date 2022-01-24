package main

import (
	"bytes"
	"flag"
	"fmt"
	"os/exec"
	"strings"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

/*
提供一个小脚本用于把同一个镜像打上不同的tag后批量推送镜像到阿里云上，测试使用
*/

func main() {
	var image string
	var url string
	var username string
	var password string
	var ns string
	flag.StringVar(&image, "image", "image", "需要push到阿里云上的镜像，本地保证存在，如：redis:latest")
	flag.StringVar(&url, "url", "url", "阿里云地址:如registry.cn-qingdao.aliyuncs.com")
	flag.StringVar(&username, "username", "username", "username")
	flag.StringVar(&password, "password", "password", "password")
	flag.StringVar(&ns, "ns", "ns", "阿里云上所建立的命名空间，需要提前建好")
	flag.Parse()
	if err := worker(image, url, username, password, ns); err != nil {
		logging.GetLogger().Err(err).Msg("worker")
	}
	logging.GetLogger().Info().Msg("push完成")
}

func worker(preImage string, url, username, password, ns string) error {
	if url == "" || username == "" || password == "" {
		logging.GetLogger().Info().Msg("url or username or password is empty")
		return fmt.Errorf("url or username or password is empty")
	}

	if err := login(url, username, password); err != nil {
		logging.GetLogger().Error().Err(err).Msg("login")
		return err
	}
	for i := 0; i < 100; i++ {
		after := changeTage(url+"/"+ns, fmt.Sprintf("redis%d", i+22), fmt.Sprintf("v%d", i))
		if err := reTage(preImage, after); err != nil {
			logging.GetLogger().Err(err).Msg("reTage")
			continue
		}
		if err := pushImage(after); err != nil {
			logging.GetLogger().Err(err).Msg("pushImage")
			continue
		}
		if err := rmImage(after); err != nil {
			logging.GetLogger().Err(err).Msg("rmImage")
			continue
		}
	}

	return nil
}

func changeTage(aliri string, imageName, tag string) string {
	return aliri + "/" + imageName + ":" + tag
}

func reTage(pre, after string) error {
	osCmd := exec.Command("docker", "tag", pre, after)
	var stdout, stderr bytes.Buffer
	osCmd.Stdout = &stdout // 标准输出
	osCmd.Stderr = &stderr // 标准错误
	err := osCmd.Run()
	if err != nil {
		logging.GetLogger().Info().Msgf("docker args:%v", osCmd.Args)
		logging.GetLogger().Info().Msgf("docker err:%s", stderr.String())
		logging.GetLogger().Error().Err(err).Msgf("docker retag pre:%s,after:%s", pre, after)
		return err
	}
	logging.GetLogger().Debug().Msgf("docker retag:%s", stdout.String())
	return nil
}

func login(url, username, password string) error {
	osCmd := exec.Command("docker", "login", "-u", username, "-p", password, getLib(url))
	logging.GetLogger().Debug().Msgf("login success %v", osCmd.Args)

	err := osCmd.Run()
	if err != nil {
		logging.GetLogger().Error().Err(err).Msgf("login failed:%v", osCmd.Args)
		return err
	}
	logging.GetLogger().Debug().Msg("login successful")
	return nil
}

func pushImage(image string) error {

	osCmd := exec.Command("docker", "push", image)
	err := osCmd.Run()
	if err != nil {
		logging.GetLogger().Error().Err(err).Msgf("docker push :%s", image)
		return err
	}
	logging.GetLogger().Info().Msgf("docker push successful :%s", image)
	return nil
}

func rmImage(imageName string) error {
	osCmd := exec.Command("docker", "rmi", "-f", imageName)

	err := osCmd.Run()
	if err != nil {
		logging.GetLogger().Error().Err(err).Msgf("docker delete image：%s:%v", imageName, osCmd.Args)
		return err
	}
	logging.GetLogger().Info().Msgf("docker delete image：%s", imageName)

	return nil
}

func getLib(url string) string {
	lib := strings.Replace(url, "http://", "", -1)
	lib = strings.Replace(lib, "https://", "", -1)

	return lib
}
