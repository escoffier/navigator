package main

import (
	"bufio"
	"fmt"
	"hash/crc32"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"

	log "github.com/sirupsen/logrus"
)

type WhitelistFile struct {
	Name     string
	Checksum string
}

var table [256]uint32

func calculateChecksum(file *os.File) (uint32, error) {
	stats, err := file.Stat()
	if err != nil {
		log.Errorf("Failed to stat file: %w\n", err)
		return uint32(0), err
	}

	var size int64 = stats.Size()
	content := make([]byte, size)

	bufr := bufio.NewReader(file)
	_, err = bufr.Read(content)
	if err != nil {
		log.Errorf("Failed to read file: %w\n", err)
		return uint32(0), err
	}

	return crc32.ChecksumIEEE(content), nil
}

func isExec(mode os.FileMode) bool {
	return mode&0111 != 0
}

func unique(slice []WhitelistFile) []WhitelistFile {
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

func listDirContents(path string, whitelist *[]WhitelistFile) {
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
			log.Errorf("Failed to resolve symlink: path %s resolvedPath %s err %w\n", newPath, resolvedSymlink, err)
			continue
		}
		if f.IsDir() {
			listDirContents(newPath, whitelist)
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

			checksum, err := calculateChecksum(file)
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

func main() {
	for i := range table {
		word := uint32(i)
		for j := 0; j < 8; j++ {
			if word&1 == 1 {
				word = (word >> 1) ^ 0xedb88320
			} else {
				word >>= 1
			}
		}
		table[i] = word
	}

	whitelist := make([]WhitelistFile, 0)

	listDirContents("/", &whitelist)

	whitelist = unique(whitelist)
	sort.Slice(whitelist, func(i, j int) bool {
		return whitelist[i].Name < whitelist[j].Name
	})

	if _, err := os.Stat("/tmp/tensorsec"); os.IsNotExist(err) {
		err = os.Mkdir("/tmp/tensorsec", os.FileMode(0777))
	}

	file, err := os.OpenFile(
		"/tmp/tensorsec/whitelist.txt",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Errorf("Failed to open whitelist file: %w\n", err)
		return
	}

	defer func() {
		if err = file.Close(); err != nil {
			log.Errorf("Failed to close whitelist file: %w\n", err)
		}
	}()

	datawriter := bufio.NewWriter(file)

	defer func() {
		if err = datawriter.Flush(); err != nil {
			log.Errorf("Failed to flush to whitelist file: %w\n", err)
		}
	}()

	for _, file := range whitelist {
		_, err = datawriter.WriteString(file.Name + " " + fmt.Sprint(file.Checksum) + "\n")
		if err != nil {
			log.Errorf("Failed to append to whitelist file: %w\n", err)
		}
	}
}
