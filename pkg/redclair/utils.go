package redclair

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	dockerarchive "github.com/docker/docker/pkg/archive"
)

// FileSignature ...
type FileSignature struct {
	Name        string `json:"name"`
	Digest      string `json:"digest"`
	Size        int64  `json:"size"`
	HeadContent []byte `json:"head_content"`
}

// GetImageFileHash ...
func GetImageFileHash(file *tar.Reader, fileHeadSize int) (FileSignature, error) {
	var err error
	var content, headContent []byte
	if content, err = ioutil.ReadAll(file); err != nil {
		return FileSignature{}, err
	}
	fileHash := sha256.New()
	if len(content) >= fileHeadSize && fileHeadSize >= 0 {
		headContent = content[0:fileHeadSize]
	} else {
		headContent = content
	}
	if _, err = io.Copy(fileHash, bytes.NewReader(content)); err != nil {
		return FileSignature{}, err
	}
	fileHashByte := fileHash.Sum(nil)
	fileHashDigest := hex.EncodeToString(fileHashByte)
	return FileSignature{
		Digest:      fileHashDigest,
		HeadContent: headContent,
	}, nil
}

func walkTarFiles(
	tarFileName string,
	maxSize int64,
	fileHeadSize int,
	ignoreRegExp *regexp.Regexp,
	softwareRegExp *regexp.Regexp,
	sensitiveRegExp *regexp.Regexp,
) ([]FileSignature, []FileSignature, []FileSignature, error) {
	// Only return file of 0 < size < [maxSize]
	// Filename should not matched with [ignoreRegExp], it is a list
	// Head [fileHeadSize] bytes of file will return
	// fileHeadSize = 0 means return no head content
	// fileHeadSize = -1 means return ALL content of file,
	// it is VERY HEAVY for memory but NOT heavy for efficiency

	rawFileReader, err := os.Open(tarFileName)
	if err != nil {
		return []FileSignature{}, []FileSignature{}, []FileSignature{}, err
	}
	if rawFileReader == nil {
		return []FileSignature{}, []FileSignature{}, []FileSignature{}, err
	}
	fileReader, err := dockerarchive.DecompressStream(rawFileReader)
	if err != nil {
		return []FileSignature{}, []FileSignature{}, []FileSignature{}, err
	}
	if fileReader == nil {
		return []FileSignature{}, []FileSignature{}, []FileSignature{}, err
	}
	tarReader := tar.NewReader(fileReader)
	var result []FileSignature
	var softwareFiles []FileSignature
	var sensitiveFiles []FileSignature
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return []FileSignature{}, []FileSignature{}, []FileSignature{}, err
		}
		if sensitiveRegExp.FindString(header.Name) != "" {
			fileSignature, err := GetImageFileHash(tarReader, -1)
			fileSignature.Name = header.Name
			fileSignature.Size = header.Size
			if err == nil {
				sensitiveFiles = append(sensitiveFiles, fileSignature)
			}
		}
		if softwareRegExp.FindString(header.Name) != "" {
			fileSignature, err := GetImageFileHash(tarReader, -1)
			fileSignature.Name = header.Name
			fileSignature.Size = header.Size
			if err == nil {
				softwareFiles = append(softwareFiles, fileSignature)
			}
		}
		if header.Typeflag == tar.TypeReg &&
			0 < header.Size && header.Size <= maxSize &&
			ignoreRegExp.Find([]byte(header.Name)) == nil {
			fileSignature, err := GetImageFileHash(tarReader, fileHeadSize)
			fileSignature.Name = header.Name
			fileSignature.Size = header.Size
			if err == nil {
				result = append(result, fileSignature)
			}
		}
	}
	return result, softwareFiles, sensitiveFiles, nil
}

func distinctFileHash(src []FileSignature) (ret []FileSignature) {
	var result []FileSignature
	var hashSet = make(map[string]struct{})
	for _, v := range src {
		if _, exist := hashSet[v.Digest]; !exist {
			result = append(result, v)
			hashSet[v.Digest] = struct{}{}
		}
	}
	return result
}

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
