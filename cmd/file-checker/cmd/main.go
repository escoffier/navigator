package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"

	log "github.com/sirupsen/logrus"
	filecheck "gitlab.com/piccolo_su/vegeta/cmd/file-checker"
)

func main() {

	whitelist := make([]filecheck.WhitelistFile, 0)

	filecheck.ListDirContents("/", &whitelist)

	whitelist = filecheck.Unique(whitelist)
	sort.Slice(whitelist, func(i, j int) bool {
		return whitelist[i].Name < whitelist[j].Name
	})

	// if _, err := os.Stat("/tmp/tensorsec"); os.IsNotExist(err) {
	// 	err = os.Mkdir("/tmp/tensorsec", os.FileMode(0777))
	// }

	file, err := os.OpenFile(
		"/tmp/whitelist.txt",
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
