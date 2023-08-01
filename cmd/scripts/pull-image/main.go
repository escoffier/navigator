package main

// import (
// 	"bufio"
// 	"flag"
// 	"fmt"
// 	"io"
// 	"os"
// 	"os/exec"
// 	"strings"
//
// 	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/warehouse"
// 	"gitlab.com/piccolo_su/vegeta/pkg/logging"
// 	"gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
// )
//
// func main() {
// 	// 用户
// 	var username string
// 	// 密码
// 	var password string
// 	// 仓库地址
// 	var url string
// 	// 镜像文件
// 	var file string
//
// 	// StringVar用指定的名称、控制台参数项目、默认值、使用信息注册一个string类型flag，并将flag的值保存到p指向的变量
// 	flag.StringVar(&username, "u", "admin", "用户名,默认:admin")
// 	flag.StringVar(&password, "p", "", "密码,默认为空")
// 	flag.StringVar(&url, "l", "127.0.0.1", "主机名,默认 127.0.0.1")
// 	flag.StringVar(&file, "f", "", "镜像文件名，默认为空")
// 	flag.Parse()
//
// 	if err := worker(url, username, password, file); err != nil {
// 		return
// 	}
// }
//
// func worker(url, username, password, file string) error {
//
// 	if err := login(url, username, password); err != nil {
// 		return err
// 	}
// 	var reg warehouse.Registry
// 	hab := getHarbor(url, username, password)
// 	if hab == nil {
// 		logging.GetLogger().Error().Msg("获取harborV2出错")
// 		return fmt.Errorf("获取harborV2出错")
// 	}
// 	reg = hab
//
// 	fi, err := os.Open(file)
// 	if err != nil {
// 		logging.GetLogger().Error().Err(err).Msgf("open file:%s", file)
// 		return err
// 	}
// 	defer fi.Close()
//
// 	success, failure := 0, 0
//
// 	br := bufio.NewReader(fi)
// 	i := 0
// 	for {
// 		ima, _, err := br.ReadLine()
// 		i++
// 		if err == io.EOF {
// 			logging.GetLogger().Info().Msgf("已全部完成，完成了:%d,成功:%d,失败:%d", i, success, failure)
// 			break
// 		}
// 		if err := pullImage(string(ima)); err != nil {
// 			failure++
// 			continue
// 		}
// 		if err := checkProject(reg, string(ima)); err != nil {
// 			_ = rmImage(string(ima))
// 			failure++
// 			continue
// 		}
//
// 		if err := pushImage(url, string(ima)); err != nil {
// 			_ = rmImage(string(ima))
// 			_ = rmImage(changeTage(string(ima), getLib(url)))
// 			failure++
// 			continue
// 		}
// 		_ = rmImage(string(ima))
// 		_ = rmImage(changeTage(string(ima), getLib(url)))
// 		success++
// 		if i%100 == 0 {
// 			logging.GetLogger().Info().Msgf("完成了:%d,成功:%d,失败:%d", i, success, failure)
// 			// 每隔一会儿就登录一次
// 			if err := login(url, username, password); err != nil {
// 				logging.GetLogger().Error().Err(err).Msgf("登录失败，已完成：%d 行，对应的镜像是:%s", i, string(ima))
// 				return err
// 			}
// 			hab := getHarbor(url, username, password)
// 			if hab == nil {
// 				logging.GetLogger().Error().Msg("获取harborV2出错")
// 				logging.GetLogger().Error().Err(err).Msgf("登录失败，已完成：%d 行，对应的镜像是:%s", i, string(ima))
// 				return fmt.Errorf("获取harborV2出错")
// 			}
// 			reg = hab
// 		}
// 	}
// 	return nil
// }
//
// func changeTage(pre, lib string) string {
// 	return lib + "/" + pre
// }
//
// func login(url, username, password string) error {
// 	osCmd := exec.Command("docker", "login", "-u", username, "-p", password, getLib(url))
// 	logging.GetLogger().Info().Msgf("登录返回：%v", osCmd.Args)
//
// 	err := osCmd.Run()
// 	if err != nil {
// 		logging.GetLogger().Error().Err(err).Msg("登录不成功")
// 		return err
// 	}
// 	logging.GetLogger().Info().Msg("登录成功")
// 	return nil
// }
//
// func pushImage(url, imageName string) error {
// 	osCmd := exec.Command("docker", "tag", imageName, changeTage(imageName, getLib(url)))
// 	err := osCmd.Run()
// 	if err != nil {
// 		logging.GetLogger().Error().Err(err).Msgf("docker 改tag出错:%s", imageName)
// 		return err
// 	}
//
// 	osCmd = exec.Command("docker", "push", changeTage(imageName, getLib(url)))
// 	err = osCmd.Run()
// 	if err != nil {
// 		logging.GetLogger().Error().Err(err).Msgf("docker 推送镜像出错:%s", changeTage(imageName, getLib(url)))
// 		return err
// 	}
// 	logging.GetLogger().Info().Msgf("docker 推送镜像成功 :%s", changeTage(imageName, getLib(url)))
// 	return nil
// }
//
// func rmImage(imageName string) error {
// 	osCmd := exec.Command("docker", "rmi", imageName)
//
// 	err := osCmd.Run()
// 	if err != nil {
// 		logging.GetLogger().Error().Err(err).Msgf("docker 删除镜像出错：%s", imageName)
// 		return err
// 	}
// 	logging.GetLogger().Info().Msgf("docker 删除镜像成功：%s", imageName)
//
// 	return nil
// }
//
// func pullImage(imageName string) error {
// 	osCmd := exec.Command("docker", "pull", imageName)
// 	err := osCmd.Run()
// 	if err != nil {
// 		logging.GetLogger().Error().Err(err).Msgf("docker 拉取镜像出错:%s", imageName)
// 		return err
// 	}
// 	logging.GetLogger().Info().Msgf("docker 拉取镜像成功 :%s", imageName)
// 	return nil
// }
//
// func getLib(url string) string {
// 	lib := strings.Replace(url, "http://", "", -1)
// 	lib = strings.Replace(lib, "https://", "", -1)
// 	return lib
// }
//
// func getHarbor(url, username, password string) warehouse.Registry {
// 	opt := make(map[string]interface{})
// 	opt["type"] = imagesec.HarborV2Version
// 	opt["url"] = url
// 	opt["username"] = username
// 	opt["password"] = password
// 	opt["skip_tls_verify"] = true
// 	opt["insecure"] = true
// 	conf := warehouse.RegistrableComponentConfig{
// 		Type:    imagesec.HarborV2Version,
// 		Options: opt,
// 	}
// 	drive, err := warehouse.Open(conf)
//
// 	if err != nil {
// 		logging.GetLogger().Error().Err(err).Msg("获取harborV2出错")
// 		return nil
// 	}
// 	return drive
// }
//
// func checkProject(reg warehouse.Registry, imaName string) error {
// 	sps := strings.Split(imaName, "/")
// 	if len(sps) <= 1 {
// 		logging.GetLogger().Info().Msgf("镜像不合法：%s", imaName)
// 		return fmt.Errorf("镜像不合法：%s", imaName)
// 	}
// 	proName := sps[0]
//
// 	if err := reg.CheckProject(proName); err == nil {
// 		logging.GetLogger().Info().Msgf("docker project已存在:%s", proName)
// 		return nil
// 	}
// 	if err := reg.CreateProject(proName, true); err != nil {
// 		logging.GetLogger().Error().Err(err).Msgf("docker project不存在，创建仓库出错:%s", proName)
// 		return nil
// 	}
// 	logging.GetLogger().Info().Msgf("docker project:%s 创建成功", proName)
// 	return nil
// }
