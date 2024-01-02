package scannerUtils

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/rs/zerolog"
	"gitlab.com/security-rd/go-pkg/logging"
)

func CopyFile(source, destination string) error {
	sourceFile, err := os.Open(source)
	if err != nil {
		return err
	}
	defer func() { _ = sourceFile.Close() }()

	desFile, err := os.Create(destination)
	if err != nil {
		return err
	}

	defer func() { _ = desFile.Close() }()

	_, err = io.Copy(desFile, sourceFile)
	if err != nil {
		return err
	}

	err = desFile.Sync()
	if err != nil {
		return err
	}
	return nil
}

func DirExists(path string) bool {
	_, err := os.Stat(path)
	if err != nil {
		if os.IsExist(err) {
			return true
		}
		return false
	}
	return true
}

func InitLogLevel(logLevel string) {
	if logLevel == "debug" {
		logging.Get().SetLevel(zerolog.DebugLevel)
	} else if logLevel == "info" {
		logging.Get().SetLevel(zerolog.InfoLevel)
	} else if logLevel == "trace" {
		logging.Get().SetLevel(zerolog.TraceLevel)
	} else if logLevel == "warn" {
		logging.Get().SetLevel(zerolog.WarnLevel)
	} else {
		// default log level is info
		logging.Get().SetLevel(zerolog.InfoLevel)
	}
}

func CleanTempDir(prefix string) error {
	if len(prefix) == 0 {
		logging.Get().Debug().Msgf("not need to clean tmp dir")
		return nil
	}

	dirs := make([]string, 0)
	_ = filepath.WalkDir("./", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// just log.but return nil to continue
			logging.Get().Err(err).Msg("walk dir err")
			return nil
		}
		if d.IsDir() && strings.HasPrefix(d.Name(), prefix) {
			dirs = append(dirs, path)
		}
		return nil
	})

	logging.Get().Debug().Interface("dirs", dirs).Msg("ready to clean tmp dir")
	for _, v := range dirs {
		_ = os.RemoveAll(v)
	}

	return nil
}

func FileSize(filePath string) (int64, error) {
	fi, err := os.Stat(filePath)
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}

func FilePerm(filePath string) (string, error) {
	fi, err := os.Stat(filePath)
	if err != nil {
		return "", err
	}
	return fi.Mode().String(), nil
}

func FileUID(filePath string) (int64, error) {
	fi, err := os.Stat(filePath)
	if err != nil {
		return -1, err
	}
	return int64(fi.Sys().(*syscall.Stat_t).Uid), nil
}

func FileGID(filePath string) (int64, error) {
	fi, err := os.Stat(filePath)
	if err != nil {
		return -1, err
	}
	return int64(fi.Sys().(*syscall.Stat_t).Gid), nil
}

func FileExist(filename string) bool {
	fd, err := os.Stat(filename)
	if err != nil {
		return false
	}
	if fd.IsDir() {
		return false
	}
	return true
}

// webshell文件后缀列表
var extSlice = []string{
	".php", ".php5", ".php4", ".asp", ".aspx", ".asmx", ".ashx", ".jsp",
	".jspa", ".jspx", ".jspf", ".cer", ".htaccess",
}

// 判断webshell文件后缀是否是给定的后缀
func WebshellFileExt(ext string) bool {
	for i := range extSlice {
		if extSlice[i] == ext {
			return true
		}
	}

	return false
}

func GetDirAllFilename(pa string) ([]string, error) {
	dir, err := os.ReadDir(pa)
	if err != nil {
		return nil, err
	}
	ans := make([]string, 0)
	for i := range dir {
		if dir[i].IsDir() {
			continue
		}
		ans = append(ans, fmt.Sprintf("%s/%s", pa, dir[i].Name()))
	}
	return ans, nil
}

func GetSha256Digest(di string) string {
	sp := strings.Split(di, "@")
	dig := sp[len(sp)-1]
	if !strings.HasPrefix(dig, "sha256:") {
		return ""
	}
	return sp[len(sp)-1]
}

func ParseImageName(im string) (host, repo, tag string) {
	//  contanerd 会有这样的数据，要处理
	//  digests=["docker.io/maohaoxin/syslog_upd_app_linux@sha256:b2d3f7e9af1d16382539dc3c330acc7d2d5cd2109d0eeff0f60679769bc91f55"]
	//  imageId=sha256:f66e9f553ba9899c5802abc1ebd9868f7bebe7bee406b5489d47550b8b15c210
	//  repoTags=["sha256:f66e9f553ba9899c5802abc1ebd9868f7bebe7bee406b5489d47550b8b15c210"]

	im = strings.Replace(im, "http://", "", 1)
	im = strings.Replace(im, "https://", "", 1)

	split := strings.Split(im, "@")
	if len(split) == 0 || split[0] == "" || strings.HasPrefix(split[0], "sha256:") {
		return
	}
	var nameOpts []name.Option
	nameOpts = append(nameOpts, name.Insecure)

	ref, err := name.ParseReference(split[0], nameOpts...)
	if err != nil {
		return
	}
	repo = ref.Context().RepositoryStr()
	tag = ref.Identifier()
	host = ref.Context().RegistryStr()
	return
}
