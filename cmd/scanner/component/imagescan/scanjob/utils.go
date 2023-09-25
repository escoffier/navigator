package scanjob

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/types"
)

func GetFileMd5(fi string) (string, error) {

	// 打开文件
	f, err := os.Open(fi)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	// 计算 MD5 值
	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	md5Str := hex.EncodeToString(h.Sum(nil))
	return md5Str, nil
}

func GetFileContent(fi string) ([]byte, error) {
	content, err := os.ReadFile(fi)
	if err != nil {
		return nil, err
	}
	return content, nil
}

func ParseEtcPasswd(filePath string) (map[int64]types.EtcPasswdUser, error) {
	ans := make(map[int64]types.EtcPasswdUser)
	if filePath == "" {
		return ans, nil
	}
	file, err := os.Open(filePath)
	if err != nil {
		return ans, err
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}
		user := types.EtcPasswdUser{
			Username: fields[0],
			Password: fields[1],
			// UID:      fields[2], // 暂时用不到
			GID:     fields[3],
			Comment: fields[4],
			HomeDir: fields[5],
			Shell:   fields[6],
		}

		uid, err := strconv.ParseInt(fields[2], 10, 64)
		if err != nil {
			continue
		}
		user.UID = uid
		ans[uid] = user
	}
	return ans, nil
}

func ParseEtcGroup(filePath string) (map[int64]types.EtcGroupUser, error) {
	ans := make(map[int64]types.EtcGroupUser)
	if filePath == "" {
		return ans, nil
	}
	file, err := os.Open(filePath)
	if err != nil {
		return ans, err
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, ":")
		if len(fields) < 4 {
			continue
		}
		// 解析字段
		group := types.EtcGroupUser{
			Name:     fields[0],
			Password: fields[1],
			Members:  strings.Split(fields[3], ","),
		}
		gid, err := strconv.ParseInt(fields[2], 10, 64)
		if err != nil {
			continue
		}
		group.GID = gid
		ans[gid] = group
	}
	return ans, nil
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
