package whitelist

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/docker/docker/api/types"
	"gitlab.com/security-rd/go-pkg/logging"
)

type imageInfo struct {
	WhiteList []WhitelistFile
}

type WhitelistCount struct {
	ImageWhiteListMap map[string]map[string]string
	Mapmutex          *sync.Mutex
	ImageDirCount     int
	HitCount          int
}

func dumpWhitelist(whiteList []WhitelistFile, outputfile string) error {
	whiteList = Unique(whiteList)
	sort.Slice(whiteList, func(i, j int) bool {
		return whiteList[i].Name < whiteList[j].Name
	})
	logging.Get().Fatal().Msgf("white list len:%v", len(whiteList))

	// write to file
	file, err := os.OpenFile(
		outputfile,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logging.Get().Fatal().Msgf("Failed to open whitelist file: %v\n", err)
		return err
	}

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

func (wc *WhitelistCount) MakeWhiteListByOverLay(image types.ImageInspect) (imageInfo, error) {

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

	whiteList := wc.walkDir(imageDir)
	logging.Get().Debug().Msgf("white list len: %d\n", len(whiteList))
	// dumpWhitelist(whiteList, whiteListName)
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
