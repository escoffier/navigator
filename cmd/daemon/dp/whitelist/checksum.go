package whitelist

import (
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	// "path/filepath"

	"gitlab.com/security-rd/go-pkg/logging"
)

const (
	hashByteRange int64 = 1024
	MaxBufferSize int64 = 1024 * 1024 * 20
)

var (
	contentbuf = make([]byte, MaxBufferSize)
)

type WhitelistFile struct {
	Name     string
	Checksum string
}

func FileHashCrc32(path string, size int64) uint32 {
	var crc uint32

	if f, err := os.Open(path); err == nil {
		defer f.Close()
		buf := make([]byte, hashByteRange)

		// explore leading section
		if n, err := f.Read(buf); err == nil {
			crc = crc32.ChecksumIEEE(buf[:n])
		}
		if size > hashByteRange {
			// explore ending section
			f.Seek(-hashByteRange, io.SeekEnd)
			if n, err := f.Read(buf); err == nil {
				crc += crc32.ChecksumIEEE(buf[:n])

			}
		}

		crc += uint32(size)
	}
	return crc
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
	files, err := ioutil.ReadDir(path)
	if err != nil {
		logging.Get().Warn().Err(err).Msgf("read dir %v error", path)
		return
	}

	for _, f := range files {
		var newPath string
		if path != "/" {
			newPath = fmt.Sprintf("%s/%s", path, f.Name())
		} else {
			newPath = fmt.Sprintf("%s%s", path, f.Name())
		}
		resolvedSymlink, err := filepath.EvalSymlinks(newPath)

		// log.Debug("resolvedSymlink: ", resolvedSymlink, "newPath: ", newPath)

		if err != nil {
			logging.Get().Warn().Msgf("Failed to resolve symlink: path %s resolvedPath %s err %v\n", newPath, resolvedSymlink, err)
			continue
		}
		if f.IsDir() {
			ListDirContents(newPath, whitelist)
		} else if f.Mode().IsRegular() && isExec(f.Mode()) {
			// if we use /proc/pid/root,then do not use resolveSymlink
			// file, err := os.Open(resolvedSymlink)
			file, err := os.Open(newPath)
			stats, err := file.Stat()
			if err != nil {
				logging.Get().Warn().Msgf("Failed to stat file: %v\n", err)
				continue
			}
			checksum := FileHashCrc32(newPath, stats.Size())

			*whitelist = append(*whitelist, WhitelistFile{
				Name:     newPath,
				Checksum: fmt.Sprintf("%X", checksum),
			})

			if err = file.Close(); err != nil {
				logging.Get().Error().Msgf("Failed to close file: path %s err %v\n", newPath, err)
			}
		}
	}
}

func execFileName(path string) (string, error) {
	pos := strings.LastIndex(path, "/")
	if pos == -1 {
		return "", fmt.Errorf("path with wrong format,not find exec file")
	}
	return path[pos+1:], nil
}

var imagePathReg = regexp.MustCompile(`(.*)(diff|merged|work)`)
var relativePathReg = regexp.MustCompile(`../`)

func travelUpperDir(path string) (string, bool) {
	pos := strings.LastIndex(path, "/")
	if pos == -1 {
		// reach end
		return path, true
	}
	path = path[:pos]
	return path, false
}

func relativePathToRealPath(relativePath, origPath string) (string, error) {
	key := "../"
	keyLen := len(key)
	end := false
	for {
		pos := strings.Index(relativePath, key)
		if pos == -1 {
			// move to one more upper dir
			origPath, end = travelUpperDir(origPath)
			if end {
				return "", fmt.Errorf("origpath no mtach relative path")
			}
			break
		}
		pos += keyLen
		relativePath = relativePath[pos:]

		origPath, end = travelUpperDir(origPath)
		if end {
			break
		}
	}
	realpath := filepath.Join(origPath, relativePath)
	return realpath, nil
}

// ImageSymLinkRealPath change sym link path to real path
// eg: /var/lib/docker/overlay2/xxx/diff/lib64/ld-linux-x86-64.so.2 -> /lib/x86_64-linux-gnu/ld-2.27.so
// change to:/var/lib/docker/overlay2/xxx/diff/lib/x86_64-linux-gnu/ld-2.27.so
func ImageSymLinkRealPath(path, linkPath string) (string, error) {
	if strings.HasPrefix(linkPath, "/") {
		res := imagePathReg.FindStringSubmatch(path)
		if len(res) < 3 {
			return "", fmt.Errorf("regexp image path err")
		}
		realpath := filepath.Join(res[1], res[2], linkPath)
		return realpath, nil
	} else if strings.HasPrefix(linkPath, "..") {
		// eg: "/overlay2/xxx/diff/lib/mail -> ../mail" change to "/overlay2/xxx/diff/mail"
		realpath, err := relativePathToRealPath(linkPath, path)
		if err != nil {
			return "", err
		}
		return realpath, nil
	} else {
		// link in current dir,eg:ld-xxx.so->bin.so
		pos := strings.LastIndex(path, "/")
		if pos == -1 {
			return path, fmt.Errorf("path format err:%s", path)
		}
		realpath := path[:pos+1] + linkPath
		return realpath, nil
	}

}

// removeCrossRefLink remove all cross ref link
// eg: linka->linkb,linkb->linka these cross ref link will be removed
func removeCrossRefLink(linkTarget map[string]string) map[string]string {
	res := make(map[string]string)
	for link, target := range linkTarget {
		// eg: linka->linkb, check if map[linkb] equal linka
		tmp, ok := linkTarget[target]
		if ok && tmp == link {
			// recur link: linka->linkb,linkb->linka
			continue
		}
		res[link] = target
	}
	return res
}

// getLinkRealPath find realpath for link
// eg: linka->linkb,linkb->mail, this func will return "mail" for linka
func getLinkRealPath(target string, linkTarget map[string]string) string {
	tmpLink := target
	tmpTarget, ok := linkTarget[tmpLink]
	if ok {
		// find target in map key which means target is a link,so recur check
		return getLinkRealPath(tmpTarget, linkTarget)
	}
	// not found target in map key which means it's realpath
	return target
}

// mergeLinkTarget for link2->link1->exec,
// original map : link2->link1,link1->exec
// change to : link2->exec,link1->exec
func rebuildLinkTarget(linkTarget map[string]string) map[string]string {
	// first remove cross ref link
	tmp := removeCrossRefLink(linkTarget)
	//log.Debugf("after remove cross link:%+v", linkTarget)

	// check real path for every link
	res := make(map[string]string)
	for linkPath, target := range tmp {
		realpath := getLinkRealPath(target, tmp)
		res[linkPath] = realpath
	}
	return res
}

func mergeLinkToWhitelist(linkTarget map[string]string, whitelist map[string]string) {
	for link, target := range linkTarget {
		_, ok := whitelist[target]
		if !ok {
			logging.Get().Warn().Msgf("not found link taget hash,maybe target is not exist: %s, %s,", link, target)
			continue
		}
		whitelist[link] = whitelist[target]
	}
}

func ListDirContentsNew(overlayDir, path string, whitelist, linkTarget map[string]string) {
	// link -> target
	//linkTarget := make(map[string]string)

	files, _ := ioutil.ReadDir(path)

	for _, f := range files {
		newPath := filepath.Join(path, f.Name())
		if f.IsDir() {
			// check if dir first,symlink may be a dir
			ListDirContentsNew(overlayDir, newPath, whitelist, linkTarget)
		} else if f.Mode().Type() == fs.ModeSymlink {
			symLinkPath, err := os.Readlink(newPath)
			if err != nil {
				logging.Get().Warn().Msgf("eval symlink %s ,err:%v", newPath, err)
				continue
			}

			realPath, err := ImageSymLinkRealPath(newPath, symLinkPath)
			if err != nil {
				logging.Get().Warn().Msgf("parse image symlink realpath err:%v,path:%s,symlink:%s", err, newPath, symLinkPath)
				continue
			}
			//log.Debugf("parse link ok,path:%s,link %s,real path:%s", newPath, symLinkPath, realPath)

			// check link target exists
			if fi, err := os.Stat(realPath); err == nil {
				if fi.IsDir() {
					// bypass link dir
					//log.Debugf("link %s is a dir,not record", fi.Name())
				} else if fi.Mode().IsRegular() && !isExec(fi.Mode()) {
					// bypass non-exec file
					//log.Debugf("link %s is not a executable file", fi.Name())
				} else {
					// newPath is exec or another link
					// trim overlay dir
					tmpPath := strings.TrimPrefix(newPath, overlayDir)
					tmpRealPath := strings.TrimPrefix(realPath, overlayDir)
					linkTarget[tmpPath] = tmpRealPath
				}
			} else if errors.Is(err, os.ErrNotExist) {
				// there is one occasion: target and link in different layer,so we still record it
				// we will do some check when rebuild link target map
				// Dockerfile example:
				// COPY test.sh /
				// RUN ln -s link1 /test.sh
				logging.Get().Debug().Msgf("link target not exist,still record:%s", realPath)
				tmpPath := strings.TrimPrefix(newPath, overlayDir)
				tmpRealPath := strings.TrimPrefix(realPath, overlayDir)
				linkTarget[tmpPath] = tmpRealPath
			} else {
				logging.Get().Error().Msgf("check link target error:%v,%s", err, realPath)
			}

		} else if f.Mode().IsRegular() && isExec(f.Mode()) {
			checksum := FileHashCrc32(newPath, f.Size())
			tmpPath := strings.TrimPrefix(newPath, overlayDir)
			whitelist[tmpPath] = fmt.Sprintf("%X", checksum)
		}
	}

}
