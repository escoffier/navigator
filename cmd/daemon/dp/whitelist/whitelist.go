package whitelist

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/rand"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	"gitlab.com/security-rd/go-pkg/logging"
)

type imageInfo struct {
	WhiteList []WhitelistFile
}

const (
	whiteListBackFileTemplate = "/host/tmp/.whitelistcache/%s.txt"
	backFilePath              = "/host/tmp/.whitelistcache"
	letterBytes               = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

type WhitelistCount struct {
	ImageWhiteListMap map[string]map[string]string
	Mapmutex          *sync.Mutex
	ImageDirCount     int
	HitCount          int
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

func init() {
	rand.Seed(time.Now().UnixNano())
}
func randString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func dumpWhitelist(whiteList []WhitelistFile, outputFile string) error {
	whiteList = Unique(whiteList)
	sort.Slice(whiteList, func(i, j int) bool {
		return whiteList[i].Name < whiteList[j].Name
	})
	logging.Get().Debug().Msgf("white list len:%v", len(whiteList))

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

	for _, file := range whiteList {
		_, err = datawriter.WriteString(file.Name + " " + fmt.Sprint(file.Checksum) + "\n")
		if err != nil {
			logging.Get().Fatal().Msgf("Failed to append to whitelist file: %v\n", err)
		}
	}
	return nil
}

func (wc *WhitelistCount) walkDir(imageDir []string) []WhitelistFile {

	logging.Get().Debug().Msgf("image dir:%v", imageDir)

	// loop dir
	// whiteList := make([]WhitelistFile, 0)
	whiteList := make(map[string]string)
	linkTarget := make(map[string]string)
	for i := range imageDir {
		// lowerDirs seq reference https://wiki.archlinux.org/title/Overlay_filesystem
		// and https://docs.docker.com/storage/storagedriver/overlayfs-driver/
		v := imageDir[len(imageDir)-i-1]
		logging.Get().Debug().Msgf("check image dir:%v", v)
		if v == "" {
			continue
		}

		wc.Mapmutex.Lock()
		wc.ImageDirCount++
		if _, ok := wc.ImageWhiteListMap[v]; ok {
			logging.Get().Debug().Msgf("image dir:%v already in white list", v)
			wc.HitCount++
			for k, v := range wc.ImageWhiteListMap[v] {
				whiteList[k] = v
			}
			wc.Mapmutex.Unlock()
			continue
		}
		wc.Mapmutex.Unlock()

		ListDirContentsNew(v, v, whiteList, linkTarget)

		// rebuild link target
		reLinkTarget := rebuildLinkTarget(linkTarget)
		if len(reLinkTarget) != len(linkTarget) {
			logging.Get().Debug().Msgf("linkTarget cnt:%d,after rebuild:%d", len(linkTarget), len(reLinkTarget))
		}

		// check link hash and add to whitelist
		mergeLinkToWhitelist(reLinkTarget, whiteList)

		wc.Mapmutex.Lock()
		if wc.ImageWhiteListMap[v] == nil {
			wc.ImageWhiteListMap[v] = make(map[string]string)
		}
		wc.ImageWhiteListMap[v] = whiteList
		wc.Mapmutex.Unlock()
	}

	retWhiteList := make([]WhitelistFile, 0)
	for file, checksum := range whiteList {
		retWhiteList = append(retWhiteList, WhitelistFile{Name: file, Checksum: checksum})
	}
	return retWhiteList

	// _ = dumpWhitelist(whiteList)
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

func (wc *WhitelistCount) MakeWhiteListByOverLay(image types.ImageInspect) (imageInfo, error) {
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
	whiteListFileName := fmt.Sprintf(whiteListBackFileTemplate, arr[1])
	var whiteList []WhitelistFile
	if isFile(whiteListFileName) {
		logging.Get().Debug().Msg("get from file")
		whiteList, err := loadWhiteListFromFile(whiteListFileName)
		if err != nil {
			logging.Get().Warn().Err(err).Msg("get white list from file fail")
		} else {
			imageInfo := imageInfo{WhiteList: whiteList}
			return imageInfo, nil
		}
	}

	imageDirKeys := []string{"MergedDir", "WorkDir", "UpperDir", "LowerDir"}
	imageDir := make([]string, 0)
	for _, key := range imageDirKeys {
		tmpDirs := strings.Split(image.GraphDriver.Data[key], ":")
		for _, v := range tmpDirs {
			if v == "" {
				continue
			}
			targetPath := v
			_, err := os.Stat("/host")
			if err == nil {
				targetPath = fmt.Sprintf("/host%s", v)
			}
			imageDir = append(imageDir, targetPath)
		}
	}
	whiteList = wc.walkDir(imageDir)
	dumpWhitelist(whiteList, whiteListFileName)
	imageInfo := imageInfo{WhiteList: whiteList}
	return imageInfo, nil
}

func (wc *WhitelistCount) CleanWhiteListCount() {
	wc.Mapmutex.Lock()
	wc.ImageWhiteListMap = make(map[string]map[string]string)
	wc.ImageDirCount = 0
	wc.HitCount = 0
	wc.Mapmutex.Unlock()
}

func NewWhitelistHandler() *WhitelistCount {
	wc := &WhitelistCount{
		ImageWhiteListMap: make(map[string]map[string]string),
		Mapmutex:          &sync.Mutex{},
		ImageDirCount:     0,
		HitCount:          0}
	return wc
}
