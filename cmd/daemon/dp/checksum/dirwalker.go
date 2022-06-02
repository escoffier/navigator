package checksum

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"sync"

	"gitlab.com/security-rd/go-pkg/logging"
)

var (
	GlobalImageWhiteListMap = map[string][]WhitelistFile{}
	Mapmutex                sync.Mutex
)

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

func WalkDir(imageDir []string) []WhitelistFile {

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

		targetPath := v
		_, err := os.Stat("/host")
		if err == nil {
			targetPath = fmt.Sprintf("/host%s", v)
		}
		ListDirContentsNew(targetPath, targetPath, whiteList, linkTarget)

		// rebuild link target
		reLinkTarget := rebuildLinkTarget(linkTarget)
		if len(reLinkTarget) != len(linkTarget) {
			logging.Get().Debug().Msgf("linkTarget cnt:%d,after rebuild:%d", len(linkTarget), len(reLinkTarget))
		}

		// check link hash and add to whitelist
		mergeLinkToWhitelist(reLinkTarget, whiteList)
	}

	retWhiteList := make([]WhitelistFile, 0)
	for file, checksum := range whiteList {
		retWhiteList = append(retWhiteList, WhitelistFile{Name: file, Checksum: checksum})
	}
	return retWhiteList

	// _ = dumpWhitelist(whiteList)
}
