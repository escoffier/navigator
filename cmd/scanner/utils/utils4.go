package scannerUtils

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	dockerarchive "github.com/docker/docker/pkg/archive"
	"github.com/docker/docker/pkg/pools"
	"github.com/yeka/zip"

	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

func ParseEtcPasswd(filePath string) (map[int64]imagesecModel.EtcPasswdUser, error) {
	ans := make(map[int64]imagesecModel.EtcPasswdUser)
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
		user := imagesecModel.EtcPasswdUser{
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

func ParseEtcGroup(filePath string) (map[int64]imagesecModel.EtcGroupUser, error) {
	ans := make(map[int64]imagesecModel.EtcGroupUser)
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
		group := imagesecModel.EtcGroupUser{
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

func UnzipDBFile(zipFile, destDir, passwd string) error {
	_ = os.RemoveAll(destDir)

	if err := os.MkdirAll(destDir, os.ModePerm); err != nil {
		return err
	}

	zipReader, err := zip.OpenReader(zipFile)
	if err != nil {
		return err
	}
	defer func() { _ = zipReader.Close() }()

	for _, f := range zipReader.File {
		if f.IsEncrypted() {
			f.SetPassword(passwd)
		}

		if f.FileInfo().IsDir() {
			continue
		}

		inFile, err := f.Open()
		if err != nil {
			return err
		}
		sf := filepath.Join(destDir, f.Name)
		outFile, err := os.OpenFile(sf, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			_ = inFile.Close()
			return err
		}
		_, err = io.Copy(outFile, inFile)
		_ = inFile.Close()
		_ = outFile.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func ExtractDockerTar(tarFile, destDir string) error {
	_ = os.RemoveAll(destDir)
	if err := os.MkdirAll(destDir, os.ModePerm); err != nil {
		return err
	}

	file, err := os.Open(tarFile)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	decompressStreamReader, err := dockerarchive.DecompressStream(file)
	if err != nil {
		return err
	}

	defer func() { _ = decompressStreamReader.Close() }()

	tarReader := tar.NewReader(decompressStreamReader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		fd := header.FileInfo()

		// header.Name 是全称，但是没有最开始的 /
		// fd.Name()是最后一级的文件名
		if !ScanFilter(fd) {
			continue
		}
		target := filepath.Join(destDir, header.Name)
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.ModePerm); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := SaveFileFromTarReader(tarReader, target); err != nil {
				return err
			}
		}
	}

	return nil
}

func ExtractTar(tarFile, targetDir string) error {

	_ = os.RemoveAll(targetDir)
	_ = os.MkdirAll(targetDir, os.ModePerm)

	ctx, cancelFunc := context.WithTimeout(context.Background(), 10*time.Minute)

	defer cancelFunc()
	cmd := exec.CommandContext(ctx, "tar", "-xf", tarFile, "-C", targetDir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		return err
	}
	return nil
}

func SaveFileFromTarReader(tr io.Reader, target string) error {
	bufReader := bufio.NewReader(tr)

	file, err := os.OpenFile(target, os.O_RDWR|os.O_CREATE|os.O_TRUNC, os.ModePerm)
	if err != nil {
		return err
	}

	bufWriter := bufio.NewWriter(file)
	_, err = io.Copy(bufWriter, bufReader)
	if err != nil {
		return err
	}
	err = bufWriter.Flush()
	if err != nil {
		return err
	}
	return nil
}

func ScanFilter(fi os.FileInfo) bool {
	mod := fi.Mode()
	if mod&os.ModeSymlink != 0 {
		return false
	}
	if mod&os.ModeDevice != 0 {
		return false
	}
	if mod&os.ModeNamedPipe != 0 {
		return false
	}
	if mod&os.ModeSymlink != 0 {
		return false
	}
	if mod&os.ModeSocket != 0 {
		return false
	}
	if mod&os.ModeSocket != 0 {
		return false
	}
	if fi.Size() == 0 {
		return false
	}
	if FilterWebshell(fi) || FilterMalware(fi) {
		return true
	}
	return false

}

var webshellMap = map[string]bool{
	".php":      true,
	".php5":     true,
	".php4":     true,
	".asp":      true,
	".aspx":     true,
	".asmx":     true,
	".ashx":     true,
	".jsp":      true,
	".jspa":     true,
	".jspx":     true,
	".jspf":     true,
	".cer":      true,
	".htaccess": true,
}

// 判断webshell文件后缀是否是给定的后缀
func FilterWebshell(fi os.FileInfo) bool {
	ext := filepath.Ext(fi.Name())
	return webshellMap[ext]
}

// 判断webshell文件后缀是否是给定的后缀
func FilterMalware(fi os.FileInfo) bool {
	/*
		这几个目录加白
		/proc: 包含系统进程信息。
		/sys: 包含与内核和硬件相关的信息。
		/dev: 包含设备文件。
		/run: 包含运行时信息。
		/var/log: 包含系统和应用程序日志
	*/
	if fi.IsDir() {
		dn := fi.Name()
		if !strings.HasPrefix(dn, "/") {
			dn = "/" + dn
		}

		if strings.HasPrefix(dn, "/proc") || strings.HasPrefix(dn, "/sys") ||
			strings.HasPrefix(dn, "/dev") || strings.HasPrefix(dn, "/var/log") {
			return false
		}
	}

	return true
}

func ZipByteSlice(data []byte) []byte {
	var compressedData bytes.Buffer

	gzipWriter := gzip.NewWriter(&compressedData)

	_, err := gzipWriter.Write(data)
	if err != nil {
		return data
	}

	err = gzipWriter.Close()
	if err != nil {
		return data
	}

	compressedBytes := compressedData.Bytes()
	return compressedBytes
}

func UnzipByteSlice(data []byte) []byte {
	compressedDataReader := bytes.NewReader(data)

	gzipReader, err := gzip.NewReader(compressedDataReader)
	if err != nil {
		return data
	}

	uncompressedData, err := io.ReadAll(gzipReader)
	if err != nil {
		return data
	}

	err = gzipReader.Close()
	if err != nil {
		return data
	}
	return uncompressedData
}

func ExtractDockerTar3(tarFile, destDir string) error {
	_ = os.RemoveAll(destDir)
	if err := os.MkdirAll(destDir, os.ModePerm); err != nil {
		return err
	}

	file, err := os.Open(tarFile)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	// 不能使用自带的包直接解压，一定得有这一步
	decompressStreamReader, err := dockerarchive.DecompressStream(file)
	if err != nil {
		return err
	}

	defer func() { _ = decompressStreamReader.Close() }()

	tr := tar.NewReader(decompressStreamReader)
	trBuf := pools.BufioReader32KPool.Get(tr)
	defer pools.BufioReader32KPool.Put(trBuf)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			// end of tar archive
			break
		}
		if err != nil {
			return err
		}
		trBuf.Reset(tr)
		srcData := io.Reader(trBuf)

		if err := createTarFile(destDir, hdr, srcData); err != nil {
			return err
		}
	}
	return nil
}

func createTarFile(destDir string, header *tar.Header, red io.Reader) error {
	target := filepath.Join(destDir, header.Name)
	switch header.Typeflag {
	case tar.TypeDir:
		if err := os.MkdirAll(target, os.ModePerm); err != nil {
			return err
		}
	case tar.TypeReg:
		if err := SaveFileFromTarReader(red, target); err != nil {
			return err
		}
	}
	return nil
}

func InStrSlice(va string, li []string) bool {
	for i := range li {
		if strings.TrimSpace(li[i]) == strings.TrimSpace(va) {
			return true
		}
	}
	return false
}
