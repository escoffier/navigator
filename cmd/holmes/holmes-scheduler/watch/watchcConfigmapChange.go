package watch

import (
	"github.com/fsnotify/fsnotify"
	"log"
)

var (
	watchDirs = []string{"/etc/holmes/rules.d"}
)

const (
	keyPath = "/etc/holmes/rules.d/..data"
)

func ConfigmapWatchInit(ch chan<- int, errorC chan<- error) {
	watch, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watch.Close()

	for _, path := range watchDirs {
		err = watch.Add(path)
	}

	if err != nil {
		log.Fatal(err)
	}
	log.Println("start file watch")

	for {
		select {
		case ev := <-watch.Events:
			{
				if ev.Name == keyPath {
					ch <- 0
				}
				if ev.Op&fsnotify.Create == fsnotify.Create {
					log.Println("create file: ", ev.Name)
				}
				if ev.Op&fsnotify.Write == fsnotify.Write {
					log.Println("write file: ", ev.Name)
				}
				if ev.Op&fsnotify.Remove == fsnotify.Remove {
					log.Println("delete file: ", ev.Name)
				}
				if ev.Op&fsnotify.Rename == fsnotify.Rename {
					log.Println("rename file: ", ev.Name)
				}
				if ev.Op&fsnotify.Chmod == fsnotify.Chmod {
					log.Println("mod file: ", ev.Name)
				}
			}
		case err := <-watch.Errors:
			{
				log.Println("error : ", err)
			}
		}
	}

}
