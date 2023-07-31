package imagetar

import (
	"archive/tar"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/docker/docker/api/types"
	dockerarchive "github.com/docker/docker/pkg/archive"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/dp/whitelist/analyzer"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/container"
	fs2 "gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/fs"
	"gitlab.com/security-rd/go-pkg/logging"
)

const (
	opq string = ".wh..wh..opq"
)

func init() {
	err := analyzer.RegisterAlternate(analyzer.TypeImageTar, NewAnalyzer)
	if err != nil {
		logging.Get().Err(err).Msg("failed to register image tar analyzer")
	} else {
		logging.Get().Debug().Msg("register image tar analyzer ok")
	}
}

type ImageTar struct {
	execFileSet map[string]string
}

func (i *ImageTar) Clean() error {
	return nil
}

func (i *ImageTar) Type() analyzer.Type {
	return analyzer.TypeImageTar
}

func (i *ImageTar) Require(runtimeInfo types.Info) bool {
	return false
}

func isGzipFile(filename string) bool {
	file, err := os.Open(filename)
	if err != nil {
		return false
	}
	defer file.Close()

	buffer := make([]byte, 2)
	_, err = io.ReadFull(file, buffer)
	if err != nil {
		return false
	}

	// magic number (1f 8b), ref: https://en.wikipedia.org/wiki/GZIP
	if buffer[0] == 0x1F && buffer[1] == 0x8B {
		return true
	}

	return false
}

func getImageTarsInPath(dir string) (tarFiles []string) {
	logging.Get().Debug().Msgf("walk dir %s", dir)
	dirs, err := ioutil.ReadDir(dir)
	if err != nil {
		logging.Get().Error().Msgf("read dir err:%v", err)
		return
	}
	for _, fi := range dirs {
		if fi.IsDir() {
			tmpArr := getImageTarsInPath(filepath.Join(dir, fi.Name()))
			tarFiles = append(tarFiles, tmpArr...)
		} else {
			tarFileName := filepath.Join(dir, fi.Name())
			ok := strings.HasSuffix(fi.Name(), ".tar")
			if !ok {
				if !isGzipFile(tarFileName) {
					logging.Get().Debug().Msgf("%s not image tar,ignore", fi.Name())
					continue
				}
			}

			// record tar file
			tarFiles = append(tarFiles, tarFileName)
			logging.Get().Debug().Msgf("found tarfile:%s", tarFileName)
		}
	}
	return tarFiles
}

func genWhitelistFromLayer(path string, whitelist map[string]string) ([]string, error) {
	tarFile, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to advance tarReader: %w", err)
	}
	defer func() { _ = tarFile.Close() }() // close the file

	decompressStreamReader, err := dockerarchive.DecompressStream(tarFile)
	if err != nil {
		return nil, fmt.Errorf("failed to DecompressStream: %w", err)
	}

	defer func() { _ = decompressStreamReader.Close() }() // close the decompressStreamReader
	mpLink := make(map[string]string)
	mpSum := make(map[string]string)
	tarReader := tar.NewReader(decompressStreamReader)
	var opqDirs []string
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("failed to advance tarReader: %w", err)
		}

		filePath := header.Name
		filePath = strings.TrimLeft(filepath.Clean(filePath), "/")
		fileDir, fileName := filepath.Split(filePath)

		// e.g. etc/.wh..wh..opq
		if opq == fileName {
			opqDirs = append(opqDirs, fileDir)
			continue
		}

		if header.Typeflag == tar.TypeDir {
			continue
		}
		perm := header.FileInfo().Mode().Perm()
		f := perm & os.FileMode(0111)
		if uint32(f) != 0 && header.FileInfo().Mode().IsRegular() {
			if header.Typeflag == tar.TypeLink || header.Typeflag == tar.TypeSymlink {
				mpLink[header.Name] = header.Linkname
				continue
			}
			addFileToList(header, whitelist, tarReader, mpSum)
		}
	}

	for target, link := range mpLink {
		_, ok := whitelist[target]
		if !ok {
			logging.Get().Debug().Msgf("link %s not found hash", link)
		}
		whitelist[link] = whitelist[target]
	}

	return opqDirs, nil
}

func (i *ImageTar) AnalyzeWhiteList(runtime container.Runtime, runtimeInfo container.RuntimeInfo, image container.ImageInspect) (analyzer.ExecFiles, error) {
	logging.Get().Debug().Interface("image", image.RepoTags).Msgf("start analyze")

	tmpPath := fmt.Sprintf("/tmp/%s", image.ID)
	err := os.MkdirAll(tmpPath, os.ModePerm)
	if err != nil {
		logging.Get().Err(err).Msg("mkdir fail")
		return nil, err
	}

	_, err = runtime.SaveImage(image.Namespace, strings.TrimPrefix(image.ID, "sha256:"), tmpPath)
	if err != nil {
		logging.Get().Err(err).Msg("")
		return nil, err
	}
	defer os.RemoveAll(tmpPath)

	var opqDirs []string
	tarFiles := getImageTarsInPath(tmpPath)
	for _, tarFile := range tarFiles {
		tmpOpqDirs, err := genWhitelistFromLayer(tarFile, i.execFileSet)
		if err != nil {
			logging.Get().Err(err).Msgf("make whitelist from tarfile %v", tarFile)
			break
		}
		opqDirs = append(opqDirs, tmpOpqDirs...)
	}
	for k, _ := range i.execFileSet {
		if k[0] != '/' {
			delete(i.execFileSet, k)
			logging.Get().Warn().Msgf("%s path not found", k)
		}
	}

	for _, v := range opqDirs {
		delete(i.execFileSet, v)
		logging.Get().Debug().Str("delete opq dir", v).Msg("")
	}

	logging.Get().Debug().Interface("image", image.RepoTags).Int("imageExecFileLen", len(i.execFileSet)).Msg("analyze image tar end")
	return i.execFileSet, nil
}

func addFileToList(header *tar.Header, whitelist map[string]string, tarReader *tar.Reader, mp map[string]string) {
	file, err := ioutil.TempFile("/tmp", "check")
	if err != nil {
		logging.Get().Err(err).Str("file", header.Name).Str("link", header.Linkname).Msg("failed to create tmp file")
		return
	}
	defer func() {
		err := os.Remove(file.Name())
		if err != nil {
			logging.Get().Err(err).Str("file", file.Name()).Msg("failed to remove file")
		}
	}()
	_, err = io.Copy(file, tarReader)
	if err != nil {
		logging.Get().Err(err).Str("file", header.Name).Str("link", header.Linkname).Msg("failed to copy file")
		return
	}
	if err := file.Sync(); err != nil {
		logging.Get().Err(err).Str("file", file.Name()).Msg("sync file fail")
		return
	}
	fi, err := os.Stat(file.Name())
	if err != nil {
		logging.Get().Err(err).Str("file", file.Name()).Msg("get file info fail")
		return
	}
	checksum := fs2.FileHashCrc32(file.Name(), fi.Size())

	whitelist[fmt.Sprintf("/%s", header.Name)] = fmt.Sprintf("%X", checksum)

	mp[header.Name] = fmt.Sprintf("%X", checksum)

	logging.Get().Trace().Str("file", header.Name).Str("checksum", mp[header.Name]).Msg("add exec file ok")
}

func NewAnalyzer(analyzer.RegistrableComponentConfig) (analyzer.Analyzer, error) {
	i := &ImageTar{
		execFileSet: make(map[string]string),
	}
	return i, nil
}
