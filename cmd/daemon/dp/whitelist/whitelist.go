package whitelist

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/rand"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/segmentio/kafka-go"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/dp/whitelist/analyzer"
	_ "gitlab.com/piccolo_su/vegeta/cmd/daemon/dp/whitelist/analyzer/all"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/container"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"
)

type WhitelistFile struct {
	Name     string
	Checksum string
}

type imageInfo struct {
	WhiteList []WhitelistFile
}

const (
	whiteListBackFileTemplate = "/host/tmp/.whitelistcache/%s.txt"
	backFilePath              = "/host/tmp/.whitelistcache"
	letterBytes               = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

type WhitelistCount struct {
	runtimeCli container.Runtime
	mqWriter   mq.Writer
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

func (wc *WhitelistCount) GenerateExecWhiteList(image types.ImageInspect) (imageInfo, error) {
	// FIXME: create a linear issue: try to update data structure to support local built image scanning at lingximo
	if len(image.RepoDigests) == 0 {
		logging.Get().Error().Msg("get image digest fail: local built image & no repo digest")
		return imageInfo{}, errors.New("no image digest given")
	}
	arr := strings.Split(image.RepoDigests[0], "@")
	if len(arr) != 2 {
		logging.Get().Error().Str("digests: ", strings.Join(image.RepoDigests, ",")).Msg("get image digest fail")
		return imageInfo{}, fmt.Errorf("image digest format error: %v", image.RepoDigests)
	}

	// check file cache
	whiteListFileName := fmt.Sprintf(whiteListBackFileTemplate, arr[1])
	if isFile(whiteListFileName) {
		logging.Get().Trace().Msg("get from file")
		wl, err := loadWhiteListFromFile(whiteListFileName)
		if err != nil {
			logging.Get().Warn().Err(err).Msg("get white list from file fail")
		} else if len(wl) == 0 {
			logging.Get().Error().Msg("load from file null, scan from dir")
		} else {
			return imageInfo{WhiteList: wl}, nil
		}
	}

	// analyze whitelist
	tmpWhiteList, err := analyzer.Analyze(wc.runtimeCli, image)
	if err != nil {
		logging.Get().Err(err).Msg("failed to analyze exec file list")
		return imageInfo{}, nil
	}
	logging.Get().Debug().Msgf("whitelist count:%v, imageID: %v", len(tmpWhiteList), image.ID)

	// transform data struct
	var resWhiteList []WhitelistFile
	for k, v := range tmpWhiteList {
		w := WhitelistFile{
			Name:     k,
			Checksum: v,
		}
		resWhiteList = append(resWhiteList, w)
	}

	// save whitelist result to file cache
	_ = dumpWhitelist(resWhiteList, whiteListFileName)
	// send whitelist to kafka
	_ = sendWhitelist(wc.mqWriter, strings.Trim(image.ID, "sha256:"), image.RepoTags, resWhiteList)

	return imageInfo{WhiteList: resWhiteList}, nil
}

func NewWhitelistHandler(runtime container.Runtime, mqWriter mq.Writer) *WhitelistCount {
	wc := &WhitelistCount{
		runtimeCli: runtime,
		mqWriter:   mqWriter,
	}
	return wc
}

func Unique(slice []WhitelistFile) []WhitelistFile {
	keys := make(map[string]bool)
	list := []WhitelistFile{}
	for _, entry := range slice {
		if _, value := keys[entry.Name]; !value {
			keys[entry.Name] = true
			list = append(list, entry)
		}
	}
	return list
}

func isFile(path string) bool {
	s, err := os.Stat(path)
	if err != nil {
		if os.IsExist(err) {
			return !s.IsDir()
		}
		return false
	}
	return !s.IsDir()
}

func loadWhiteListFromFile(path string) ([]WhitelistFile, error) {
	f, err := os.Open(path)
	if err != nil {
		logging.Get().Error().Msg(err.Error())
		return []WhitelistFile{}, err
	}
	defer f.Close()
	whiteList := make([]WhitelistFile, 0)
	br := bufio.NewReader(f)
	for {
		line, _, c := br.ReadLine()
		if c == io.EOF {
			break
		}
		lineStr := string(line)
		arr := strings.Split(lineStr, " ")
		if len(arr) < 2 {
			logging.Get().Error().Msgf("format err, line: %v \n", lineStr)
			continue
		}
		fileName := arr[0]
		checksum := arr[1]
		item := WhitelistFile{
			Name:     fileName,
			Checksum: checksum,
		}
		whiteList = append(whiteList, item)
	}
	return whiteList, nil
}

func randString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func dumpWhitelist(whiteList []WhitelistFile, outputFile string) error {
	if len(whiteList) <= 0 {
		return fmt.Errorf("whitelist is null, skip dump")
	}
	whiteList = Unique(whiteList)
	sort.Slice(whiteList, func(i, j int) bool {
		return whiteList[i].Name < whiteList[j].Name
	})
	logging.Get().Trace().Msgf("white list len:%v", len(whiteList))

	if _, err := os.Stat(backFilePath); err != nil {
		err = os.Mkdir(backFilePath, fs.FileMode(0x0700))
		if err != nil {
			logging.Get().Error().Msg("mkdir fail")
			return err
		}
	}
	tmpFilePath := outputFile + ".tmp." + randString(16)
	// write to file
	file, err := os.OpenFile(
		tmpFilePath,
		os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logging.Get().Fatal().Msgf("Failed to open whitelist file: %v\n", err)
		return err
	}

	defer func() {
		// reference: https://www.reddit.com/r/golang/comments/d3sg0j/how_to_atomically_write_to_files_in_go/
		if err = os.Rename(tmpFilePath, outputFile); err != nil {
			logging.Get().Fatal().Msgf("Failed rename whitelist file: %v\n", err)
		}
	}()

	defer func() {
		if err = file.Close(); err != nil {
			logging.Get().Fatal().Msgf("Failed to close whitelist file: %v\n", err)
		}
	}()

	datawriter := bufio.NewWriter(file)

	defer func() {
		if err = datawriter.Flush(); err != nil {
			logging.Get().Fatal().Msgf("Failed to flush to whitelist file: %v\n", err)
		}
	}()

	for _, fi := range whiteList {
		_, err = datawriter.WriteString(fi.Name + " " + fmt.Sprint(fi.Checksum) + "\n")
		if err != nil {
			logging.Get().Fatal().Msgf("Failed to append to whitelist file: %v\n", err)
		}
	}
	return nil
}

func transformListType(whitelist []WhitelistFile) []model.DriftWhitelistFile {
	var res []model.DriftWhitelistFile
	for _, item := range whitelist {
		res = append(res, model.DriftWhitelistFile{
			FileName: item.Name,
			Checksum: item.Checksum,
		})
	}
	return res
}

func sendWhitelist(mqWrite mq.Writer, imageID string, repoTags []string, whitelist []WhitelistFile) error {
	if len(whitelist) <= 0 {
		return fmt.Errorf("whitelist is null, skip send")
	}
	whitelist = Unique(whitelist)
	sort.Slice(whitelist, func(i, j int) bool {
		return whitelist[i].Name < whitelist[j].Name
	})
	logging.Get().Trace().Msgf("white list len:%v", len(whitelist))

	kafkaData := model.DriftImageWhitelistKafka{
		ImageID:    imageID,
		RepoTags:   repoTags,
		Whitelists: transformListType(whitelist),
	}
	msg, err := json.Marshal(kafkaData)
	if err != nil {
		logging.Get().Error().Msgf("json marshal fail, err:%v", err)
		return err
	}

	sendWhiteList2Kafka(mqWrite, model.SubjectOfDriftWhiteListEvent, msg)
	return nil
}

func sendWhiteList2Kafka(mqWrite mq.Writer, topicStr string, msg []byte) error {
	return mqWrite.Write(
		context.Background(), topicStr, kafka.Message{
			Topic: topicStr,
			Key:   []byte("support resource info"),
			Value: msg,
		})
}
