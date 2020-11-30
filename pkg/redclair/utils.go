package redclair

import (
	"archive/tar"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

func (r Redclair) CreateHTTPRootDir() (string, error) {
	rootPath := filepath.Join(os.TempDir(), httpServerRootDir)
	return rootPath, os.MkdirAll(rootPath, os.ModePerm)
}

// CreateTmpPath creates a temporary folder with a prefix
func (r Redclair) CreateTempImageDirIn(where string) (string, error) {
	rootPath := filepath.Join(os.TempDir(), httpServerRootDir)
	return ioutil.TempDir(rootPath, httpServerImageDirPrefix)
}

// CreateTempLayerDigestDir creates a temporary folder with a layer digest prefix
func (r Redclair) CreateTempLayerDigestDir(layerDigest string) (string, error) {
	rootPath := filepath.Join(os.TempDir(), httpServerRootDir)
	return ioutil.TempDir(rootPath, layerDigest)
}

// untar uses a Reader that represents a tar to untar it on the fly to a target folder
func untar(imageReader io.ReadCloser, target string) error {
	tarReader := tar.NewReader(imageReader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		path := filepath.Join(target, header.Name)
		if !strings.HasPrefix(path, filepath.Clean(target)+string(os.PathSeparator)) {
			return fmt.Errorf("%s: illegal file path", header.Name)
		}
		info := header.FileInfo()
		if info.IsDir() {
			if err = os.MkdirAll(path, info.Mode()); err != nil {
				return err
			}
			continue
		}

		file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode())
		if err != nil {
			return err
		}
		defer file.Close()
		if _, err = io.Copy(file, tarReader); err != nil {
			return err
		}
	}
	return nil
}
