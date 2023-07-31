package overlaycrio

import (
	"fmt"
	"io/fs"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/docker/docker/api/types"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/dp/whitelist/analyzer"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/container"
	fs2 "gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/fs"
	"gitlab.com/security-rd/go-pkg/logging"
)

type OverlayCRIO struct {
}

func init() {
	err := analyzer.Register(analyzer.TypeOverlayCRIO, NewAnalyzer)
	if err != nil {
		logging.Get().Err(err).Msg("failed to register overlaycrio analyzer")
	} else {
		logging.Get().Debug().Msg("register overlaycrio analyzer ok")
	}
}

func (o *OverlayCRIO) Type() analyzer.Type {
	return analyzer.TypeOverlayCRIO
}

func (o *OverlayCRIO) Require(runtimeInfo types.Info) bool {
	return strings.Contains(runtimeInfo.Driver, "overlay2")
}

func (o *OverlayCRIO) Clean() error {
	// nothing need to clean
	return nil
}

func (o *OverlayCRIO) AnalyzeWhiteList(runtime container.Runtime, runtimeInfo container.RuntimeInfo, image container.ImageInspect) (analyzer.ExecFiles, error) {
	imageDir := make([]string, 0)

	imagePaths, err := runtime.GetImageLayersDir(image.Namespace, image.ID)
	if err != nil {
		logging.Get().Err(err).Msg("failed to get image layers dir")
		return nil, err
	}
	for i := len(imagePaths) - 1; i >= 0; i-- {
		targetPath := imagePaths[i]
		logging.Get().Debug().Msgf("imageName: %v, image layer dir:%v", image.RepoTags, targetPath)
		imageDir = append(imageDir, targetPath)
	}

	whiteList := o.walkDir(imageDir)
	return whiteList, nil
}

func (o *OverlayCRIO) walkDir(imageDir []string) analyzer.ExecFiles {

	logging.Get().Trace().Msgf("image dir:%v", imageDir)

	// loop dir
	// whiteList := make([]WhitelistFile, 0)
	whiteList := make(map[string]string) // filename->checksum
	for i := range imageDir {
		// lowerDirs seq reference https://wiki.archlinux.org/title/Overlay_filesystem
		// and https://docs.docker.com/storage/storagedriver/overlayfs-driver/
		v := imageDir[len(imageDir)-i-1]
		logging.Get().Trace().Msgf("check image dir:%v", v)
		if v == "" {
			continue
		}

		// // check cache
		// if fs2.GetImageFsCache().HitCache(v, whiteList) {
		// 	logging.Get().Trace().Str("imagePath", v).Msg("hit cache")
		// 	continue
		// }

		ListDirContentsNew(v, v, whiteList)

		// // add to cache
		// fs2.GetImageFsCache().CacheResult(v, whiteList)
	}

	return whiteList
}

func ListDirContentsNew(overlayDir, path string, whitelist map[string]string) {

	files, _ := ioutil.ReadDir(path)
	for _, f := range files {
		newPath := filepath.Join(path, f.Name())
		if f.IsDir() {
			// check if dir first,symlink may be a dir
			ListDirContentsNew(overlayDir, newPath, whitelist)
		} else if f.Mode().Type() == fs.ModeSymlink {
			// dp.so will readlink of exec binary,so we bypass link here
			continue
		} else if f.Mode().IsRegular() && fs2.IsExec(f.Mode()) {
			checksum := fs2.FileHashCrc32(newPath, f.Size())
			tmpPath := strings.TrimPrefix(newPath, overlayDir)
			whitelist[tmpPath] = fmt.Sprintf("%X", checksum)
		} else {
			// not regular file,bypass
		}
	}
}

func NewAnalyzer(config analyzer.RegistrableComponentConfig) (analyzer.Analyzer, error) {
	o := &OverlayCRIO{}
	return o, nil
}
