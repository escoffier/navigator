package filecheck

import (
	"bufio"
	"fmt"
	"hash/crc32"
	"io/ioutil"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
)

type WhitelistFile struct {
	Name     string
	Checksum string
}

func CalculateChecksum(file *os.File) (uint32, error) {
	stats, err := file.Stat()
	if err != nil {
		log.Errorf("Failed to stat file: %v\n", err)
		return uint32(0), err
	}

	var size int64 = stats.Size()
	content := make([]byte, size)

	bufr := bufio.NewReader(file)
	_, err = bufr.Read(content)
	if err != nil {
		log.Errorf("Failed to read file: %v\n", err)
		return uint32(0), err
	}

	return crc32.ChecksumIEEE(content), nil
}

func isExec(mode os.FileMode) bool {
	return mode&0111 != 0
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

func ListDirContents(path string, whitelist *[]WhitelistFile) {
	files, _ := ioutil.ReadDir(path)

	for _, f := range files {
		var newPath string
		if path != "/" {
			newPath = fmt.Sprintf("%s/%s", path, f.Name())
		} else {
			newPath = fmt.Sprintf("%s%s", path, f.Name())
		}
		resolvedSymlink, err := filepath.EvalSymlinks(newPath)
		if err != nil {
			log.Errorf("Failed to resolve symlink: path %s resolvedPath %s err %v\n", newPath, resolvedSymlink, err)
			continue
		}
		if f.IsDir() {
			ListDirContents(newPath, whitelist)
		} else if f.Mode().IsRegular() && isExec(f.Mode()) {
			file, err := os.Open(resolvedSymlink)
			if err != nil {
				log.Errorf("Failed to open file: path %s resolvedPath %s err %w\n", newPath, resolvedSymlink, err)
				continue
			}
			defer func() {
				if err = file.Close(); err != nil {
					log.Errorf("Failed to close file: path %s resolvedPath %s err %w\n", newPath, resolvedSymlink, err)
				}
			}()

			checksum, err := CalculateChecksum(file)
			if err != nil {
				log.Errorf("Failed to calculate checksum: path %s resolvedPath %s err %w\n", newPath, resolvedSymlink, err)
				continue
			}
			*whitelist = append(*whitelist, WhitelistFile{
				Name:     newPath,
				Checksum: fmt.Sprintf("%X", checksum),
			})
		}
	}
}
