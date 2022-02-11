package watch

import (
	"github.com/fsnotify/fsnotify"
	"gitlab.com/security-rd/go-pkg/logging"
)

var (
	watchDirs = []string{"/etc/holmes/rules.d"}
)

const (
	keyPath = "/etc/holmes/rules.d/..data"
)

func ConfigmapWatchInit(ch chan<- struct{}, errorC chan<- error) {
	watch, err := fsnotify.NewWatcher()
	if err != nil {
		logging.Get().Err(err).Msg("fsnotify new watcher error")
		return
	}
	defer watch.Close()

	for _, path := range watchDirs {
		err = watch.Add(path)
		if err != nil {
			logging.Get().Err(err).Str("path", path).Msg("add path to watch err")
		}
	}

	logging.Get().Info().Msg("start file watch")

	for {
		select {
		case ev := <-watch.Events:
			{
				if ev.Name == keyPath {
					ch <- struct{}{}
				}
				if ev.Op&fsnotify.Create == fsnotify.Create {
					logging.Get().Info().Msgf("create file: %s", ev.Name)
				}
				if ev.Op&fsnotify.Write == fsnotify.Write {
					logging.Get().Info().Msgf("write file: %s", ev.Name)
				}
				if ev.Op&fsnotify.Remove == fsnotify.Remove {
					logging.Get().Info().Msgf("delete file: %s", ev.Name)
				}
				if ev.Op&fsnotify.Rename == fsnotify.Rename {
					logging.Get().Info().Msgf("rename file: %s", ev.Name)
				}
				if ev.Op&fsnotify.Chmod == fsnotify.Chmod {
					logging.Get().Info().Msgf("mod file: %s", ev.Name)
				}
			}
		case err := <-watch.Errors:
			logging.Get().Err(err).Msg("watch error")
		}
	}

}
