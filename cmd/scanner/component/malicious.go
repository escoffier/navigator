package component

// import (
// 	"archive/tar"
// 	"bytes"
// 	"context"
// 	"crypto/md5"
// 	"encoding/hex"
// 	"encoding/json"
// 	"fmt"
// 	"io"
// 	"io/fs"
// 	"io/ioutil"
// 	"os"
// 	"path/filepath"
// 	"strconv"
// 	"strings"
// 	"time"
// 	"unsafe"
//
// 	dockerarchive "github.com/docker/docker/pkg/archive"
// 	"github.com/segmentio/kafka-go"
// 	"gitlab.com/security-rd/go-pkg/logging"
// 	"gitlab.com/security-rd/go-pkg/mq"
//
// 	aviraCli "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/avira"
// 	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/malicious"
// 	"gitlab.com/piccolo_su/vegeta/pkg/model"
// 	scannermodel "gitlab.com/piccolo_su/vegeta/pkg/model/scanner-model"
// )
//
// type MaliciousScan struct {
// 	MaliciousSrv *malicious.MaliciousServer
// 	MqWriter     mq.Writer
// }
//
// func (m *MaliciousScan) ScanLayer(ctx context.Context, digest string, layerPath string) ([]*model.VirusInfo, error) {
// 	digestNum := strings.Split(digest, ":")[1]
// 	timeUnix := time.Now().Unix()
// 	timeUnixStr := strconv.FormatInt(timeUnix, 10)
// 	tmpDir := filepath.Join("/tmpscan/", digestNum+timeUnixStr)
// 	err := os.MkdirAll(tmpDir, 0777)
// 	if err != nil {
// 		return []*model.VirusInfo{}, err
// 		// 错误处理
// 	}
// 	defer func() { _ = os.RemoveAll(tmpDir) }()
// 	fileMap := make(map[string][]string)
// 	fileCount, err := m.parseLayerTar(layerPath, tmpDir, fileMap)
// 	if err != nil {
// 		return []*model.VirusInfo{}, fmt.Errorf("Failed to parseLayerTar: %w", err)
// 	}
//
// 	// logging.Get().Info().Msgf("fileCount :%v ", fileCount)
//
// 	if fileCount == 0 {
// 		return []*model.VirusInfo{}, nil
//
// 	}
// 	var virusInfos []*model.VirusInfo
// 	if os.Getenv("SCAN_VIRUS") == "avira" {
// 		virusInfos, err = m.aviraScan(ctx, tmpDir, digestNum)
// 		if err != nil {
// 			return []*model.VirusInfo{}, fmt.Errorf("Avira Error %w", err)
// 		}
// 	} else {
// 		virusInfos, err = m.virusScan(ctx, tmpDir)
// 		if err != nil {
// 			return []*model.VirusInfo{}, fmt.Errorf("Clamscan Error %w", err)
// 		}
// 	}
// 	res := []*model.VirusInfo{}
//
// 	for k := range virusInfos {
// 		if v, ok := fileMap[virusInfos[k].FileName]; ok {
// 			// 读文件
// 			fi := filepath.Join(virusInfos[k].FilePath, virusInfos[k].FileName)
// 			fileByte, err := os.ReadFile(fi)
// 			if err != nil {
// 				logging.Get().Err(err).Msgf("read file")
// 				continue
// 			}
// 			if len(fileByte) == 0 {
// 				continue
// 			}
// 			hash := md5.New()
// 			_, _ = io.Copy(hash, bytes.NewBuffer(fileByte))
// 			fileMd5 := hex.EncodeToString(hash.Sum(nil))
// 			saveInfo := scannermodel.WebshellSaveInfo{
// 				FileMd5:  fileMd5,
// 				Data:     fileByte,
// 				Filename: fi,
// 			}
// 			_ = m.SendKafka(saveInfo)
//
// 			for kk := range v {
// 				virus := model.VirusInfo{FileName: virusInfos[k].FileName, FilePath: v[kk], VirusName: virusInfos[k].VirusName, Md5: fileMd5}
// 				res = append(res, &virus)
// 			}
// 		}
// 	}
// 	return res, nil
// }
//
// func (m *MaliciousScan) aviraScan(ctx context.Context, scanPath string, digestNum string) ([]*model.VirusInfo, error) {
// 	logging.Get().Info().Str("scanPath", scanPath).Msg("aviraScan")
// 	result, err := aviraCli.ScanDir(scanPath)
// 	if err != nil {
// 		return []*model.VirusInfo{}, err
// 	}
// 	virusInfos := []*model.VirusInfo{}
//
// 	for path, virus := range result {
// 		virusName := make(map[string]struct{})
// 		for _, v := range virus {
// 			if _, ok := virusName[v]; !ok {
// 				virusName[v] = struct{}{}
// 				lastIndex := strings.LastIndex(path, "/")
// 				filePath := path[:lastIndex]
// 				fileName := path[lastIndex+1:]
// 				virusInfos = append(virusInfos, &model.VirusInfo{
// 					FileName:  fileName,
// 					VirusName: v,
// 					FilePath:  filePath,
// 				})
// 			}
// 		}
// 	}
//
// 	return virusInfos, nil
// }
//
// func (m *MaliciousScan) dirScan(ctx context.Context, dstPath string) []*model.VirusInfo {
// 	virusInfos := []*model.VirusInfo{}
// 	filepath.Walk(dstPath, func(path string, info fs.FileInfo, err error) error {
// 		if err != nil {
// 			return err
// 		}
// 		// if info.IsDir() {
// 		// 	m.dirScan(ctx, path, virusInfos)
// 		// }
// 		logging.Get().Info().Msgf("scan virus path is %v", path)
// 		res := m.MaliciousSrv.Scan(path)
// 		if res != "" {
// 			logging.Get().Info().Msgf("malicious scan virusName %v", res)
// 			lastIndex := strings.LastIndex(path, "/")
// 			filePath := path[:lastIndex]
// 			fileName := path[lastIndex+1:]
// 			virusInfos = append(virusInfos, &model.VirusInfo{FileName: fileName, VirusName: res, FilePath: filePath})
// 		}
// 		return nil
// 	})
// 	return virusInfos
// }
//
// func (m *MaliciousScan) virusScan(ctx context.Context, scanPath string) ([]*model.VirusInfo, error) {
// 	virusInfos := m.dirScan(ctx, scanPath)
// 	return virusInfos, nil
// }
//
// // func (m *MaliciousScan) clamavScan(ctx context.Context, scanPath string, digestNum string) ([]model.VirusInfo, error) {
// //
// // 	clamLogPath := scanPath + ".log"
// // 	cmd := exec.Command("/usr/bin/clamdscan", "--quiet", "-m", scanPath, "-l", clamLogPath)
// // 	// logging.Get().Info().Str("scanPath", scanPath).Str("clamLogPath", clamLogPath).Msg("ScanPath")
// // 	defer os.Remove(clamLogPath)
// // 	var out bytes.Buffer
// // 	var stderr bytes.Buffer
// // 	cmd.Stdout = &out
// // 	cmd.Stderr = &stderr
// // 	err := cmd.Run()
// //
// // 	if err != nil {
// // 		// 扫描到病毒时err返回值为1,所以不能退出,错误时ParseSummrylogs读不到日志文件，会返回空集。
// // 		errString := fmt.Sprintf("%s", err)
// // 		if strings.Compare("exit status 1", errString) != 0 {
// // 			zerolog.Ctx(ctx).Info().Err(err).Str("Out:", out.String()).Str("Stderr:", stderr.String()).Str("ScanPath:", scanPath).Msg("Cla ERROR")
// // 			return []model.VirusInfo{}, fmt.Errorf("ClamScan Error %w", err)
// // 		}
// // 	}
// //
// // 	zerolog.Ctx(ctx).Info().Msg("Clamscan ok")
// // 	VirusInfos := m.ParseSummrylogs(clamLogPath, scanPath)
// // 	return VirusInfos, nil
// // }
//
// func (m *MaliciousScan) ParseSummrylogs(logPath string, scanPath string) []model.VirusInfo {
// 	replaceString := scanPath
// 	ClamAvVirus := []model.VirusInfo{}
// 	reader, err := ioutil.ReadFile(logPath)
// 	if err != nil {
// 		return []model.VirusInfo{}
// 	}
// 	str := (*string)(unsafe.Pointer(&reader))
// 	strSplit := strings.Split(*str, "\n")
// 	for _, val := range strSplit {
// 		tmp := strings.Index(val, "FOUND")
// 		if tmp != -1 {
// 			tmpResult := strings.Split(val[0:tmp-1], ":")
// 			if len(tmpResult) < 2 {
// 				continue
// 			}
// 			lastIndex := strings.LastIndex(tmpResult[0], "/")
// 			fileName := tmpResult[0][lastIndex+1:]
// 			filePath := tmpResult[0][:lastIndex+1]
// 			ClamAvVirus = append(ClamAvVirus, model.VirusInfo{
// 				FileName:  fileName,
// 				FilePath:  strings.Replace(filePath, replaceString, "", 1),
// 				VirusName: tmpResult[1],
// 			})
// 		}
// 	}
// 	return ClamAvVirus
// }
//
// func (m *MaliciousScan) ParseLayerTarWebFrame(tarFileName string) ([]model.WebFrameInfo, error) {
// 	tarFile, err := os.Open(tarFileName)
// 	res := []model.WebFrameInfo{}
// 	if err != nil {
// 		return res, fmt.Errorf("Failed to advance tarReader: %w", err)
// 	}
// 	defer func() { _ = tarFile.Close() }() // close the file
//
// 	decompressStreamReader, err := dockerarchive.DecompressStream(tarFile)
// 	if err != nil {
// 		return res, fmt.Errorf("Failed to DecompressStream: %w", err)
// 	}
//
// 	defer func() { _ = decompressStreamReader.Close() }() // close the decompressStreamReader
//
// 	tarReader := tar.NewReader(decompressStreamReader)
// 	for {
// 		header, err := tarReader.Next()
// 		if err == io.EOF {
// 			break
// 		} else if err != nil {
// 			return res, fmt.Errorf("Failed to advance tarReader: %w", err)
// 		}
//
// 		// 检查类型，过滤文件夹、软链接和硬链接
// 		switch header.Typeflag {
// 		case tar.TypeDir, tar.TypeLink, tar.TypeSymlink:
// 			continue
// 		}
// 		if strings.Contains(header.Name, "Gemfile.lock") {
// 			// logging.Get().Info().Msg("find Gemfile.lock")
// 			content, err := ioutil.ReadAll(tarReader)
// 			if err != nil {
// 				continue
// 			}
// 			version := m.FindInGemfile(string(content))
// 			if version == "" {
// 				continue
// 			}
// 			tmpInfo := model.WebFrameInfo{}
// 			tmpInfo.FileName = "Gemfile.lock"
// 			tmpInfo.Version = version
// 			tmpInfo.FrameName = "rails"
// 			tmpInfo.Language = "Ruby"
// 			index := strings.LastIndex(header.Name, "/")
// 			if index == -1 {
// 				tmpInfo.FilePath = header.Name
// 			} else {
// 				tmpInfo.FilePath = header.Name[0 : index+1]
// 			}
// 			res = append(res, tmpInfo)
// 			logging.Get().Info().Msgf("web res %v", res)
// 		}
//
// 		if strings.Contains(header.Name, "composer.json") {
// 			content, err := ioutil.ReadAll(tarReader)
// 			if err != nil {
// 				continue
// 			}
// 			version := m.FindInComposer(string(content))
// 			if version == "" {
// 				continue
// 			}
// 			tmpInfo := model.WebFrameInfo{}
// 			tmpInfo.FileName = "composer.json"
// 			tmpInfo.Version = version
// 			tmpInfo.FrameName = "laravel"
// 			tmpInfo.Language = "PHP"
// 			index := strings.LastIndex(header.Name, "/")
// 			if index == -1 {
// 				tmpInfo.FilePath = header.Name
// 			} else {
// 				tmpInfo.FilePath = header.Name[0 : index+1]
// 			}
// 			res = append(res, tmpInfo)
// 		}
//
// 		if strings.Contains(header.Name, "package.json") {
// 			content, err := ioutil.ReadAll(tarReader)
// 			if err != nil {
// 				continue
// 			}
// 			tmpinfo := m.FindInPackage(string(content))
// 			if len(tmpinfo) == 0 {
// 				continue
// 			}
// 			index := strings.LastIndex(header.Name, "/")
// 			filePath := ""
// 			if index == -1 {
// 				filePath = header.Name
// 			} else {
// 				filePath = header.Name[0 : index+1]
// 			}
// 			for k := range tmpinfo {
// 				tmpinfo[k].FileName = "package.json"
// 				tmpinfo[k].FilePath = filePath
// 				tmpinfo[k].Language = "node.js"
// 			}
// 			res = append(res, tmpinfo...)
// 		}
//
// 	}
// 	return res, nil
// }
//
// func (m *MaliciousScan) FindInPackage(content string) []model.WebFrameInfo {
// 	indexExpress := strings.Index(content, "\"express\": \"")
// 	indexHapi := strings.Index(content, "\"hapi\": \"")
// 	lastExpress := indexExpress + 13
// 	res := make([]model.WebFrameInfo, 0)
// 	lastHapi := indexHapi + 10
// 	if indexExpress != -1 || indexHapi != -1 {
// 		if indexExpress != -1 {
// 			tmp := m.SubFindInPackage(content, "express", indexExpress, lastExpress)
// 			if tmp.Version != "" {
// 				res = append(res, tmp)
// 			}
// 		}
//
// 		if indexHapi != -1 {
// 			tmp := m.SubFindInPackage(content, "hapi", indexExpress, lastHapi)
// 			if tmp.Version != "" {
// 				res = append(res, tmp)
// 			}
// 		}
// 	}
// 	return res
// }
//
// func (m *MaliciousScan) SubFindInPackage(content string, ptype string, index int, lastIndex int) model.WebFrameInfo {
// 	res := model.WebFrameInfo{}
//
// 	if len(content) < lastIndex+13 {
// 		return model.WebFrameInfo{}
// 	}
// 	for k := lastIndex; k < len(content); k++ {
// 		if content[k] == '"' {
// 			version := content[lastIndex:k]
// 			res.Version = version
// 			res.FrameName = ptype
// 			break
// 		}
// 	}
//
// 	return res
// }
//
// func (m *MaliciousScan) FindInComposer(content string) string {
// 	index := strings.Index(content, "laravel/framework\":")
// 	version := ""
// 	if index != -1 {
// 		if len(content) < index+21 {
// 			return ""
// 		}
// 		for k := index + 21; k < len(content); k++ {
// 			if content[k] == '"' {
// 				version = content[index+21 : k]
// 				break
// 			}
// 		}
// 	}
//
// 	return version
// }
//
// func (m *MaliciousScan) FindInGemfile(content string) string {
// 	index := strings.Index(content, "rails (= ")
// 	logging.Get().Info().Msgf("index is %v", index)
// 	version := ""
// 	if index != -1 {
// 		if len(content) > index+9 {
// 			for k := index + 9; k < len(content); k++ {
// 				if content[k] == ')' {
// 					version = content[index+9 : k]
// 					break
// 				}
// 			}
// 		}
// 	}
//
// 	return version
// }
//
// func (m *MaliciousScan) parseLayerTar(tarFileName string, dst string, fileToPath map[string][]string) (uint64, error) {
// 	tarFile, err := os.Open(tarFileName)
// 	if err != nil {
// 		return 0, fmt.Errorf("Failed to advance tarReader: %w", err)
// 	}
// 	defer func() { _ = tarFile.Close() }() // close the file
//
// 	decompressStreamReader, err := dockerarchive.DecompressStream(tarFile)
// 	if err != nil {
// 		return 0, fmt.Errorf("Failed to DecompressStream: %w", err)
// 	}
//
// 	defer func() { _ = decompressStreamReader.Close() }() // close the decompressStreamReader
//
// 	tarReader := tar.NewReader(decompressStreamReader)
// 	var count uint64 = 0
// 	for {
// 		header, err := tarReader.Next()
// 		if err == io.EOF {
// 			break
// 		} else if err != nil {
// 			return count, fmt.Errorf("Failed to advance tarReader: %w", err)
// 		}
//
// 		// 检查类型，过滤文件夹、软链接和硬链接
// 		switch header.Typeflag {
// 		case tar.TypeDir, tar.TypeLink, tar.TypeSymlink:
// 			continue
// 		}
// 		// fmt.Println(header.Name)
// 		perm := header.FileInfo().Mode().Perm()
// 		f := perm & os.FileMode(73)
//
// 		// 判断是否需要扫描所有类型文件
// 		if os.Getenv("SCAN_ALL") != "true" {
// 			// 判断文件是否是可执行文件或者webshell后缀的文件
// 			if uint32(f) != uint32(73) {
// 				continue
// 			}
// 		}
// 		// 这里这样写防止ioutil.ReadAll读取所有的内容
// 		lastIndex := strings.LastIndex(header.Name, "/")
// 		fileName := header.Name
// 		filePath := "/"
// 		if lastIndex != -1 {
// 			fileName = header.Name[lastIndex+1:]
// 			filePath = header.Name[:lastIndex]
// 		}
// 		fileToPath[fileName] = append(fileToPath[fileName], filePath)
// 		file, _ := m.createFile(filepath.Join(dst, fileName))
// 		_, err = io.Copy(file, tarReader)
// 		if err != nil {
// 			logging.Get().Err(err).Msg("virusScan io.Copy error")
// 		}
// 		err = os.Chmod(filepath.Join(dst, fileName), 0666)
// 		if err != nil {
// 			logging.Get().Err(err).Msg("virusScan os.Chmod error")
// 		}
// 		count++
//
// 	}
// 	return count, nil
// }
//
// func (m *MaliciousScan) createFile(name string) (*os.File, error) {
// 	err := os.MkdirAll(string([]rune(name)[0:strings.LastIndex(name, "/")]), 0755)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return os.Create(name)
// }
//
// func (m *MaliciousScan) SendKafka(saveInfo scannermodel.WebshellSaveInfo) error {
// 	// if len(saveInfo.Data) == 0 {
// 	// 	logging.Get().Error().Msg("MaliciousScan file data is empty")
// 	// 	return nil
// 	// }
// 	bys, err := json.Marshal(saveInfo)
// 	if err != nil {
// 		return err
// 	}
//
// 	err = m.MqWriter.Write(context.Background(), scannermodel.WebshellKafkaTopic, kafka.Message{
// 		Key:   []byte(scannermodel.WebshellKafkaKey),
// 		Value: bys,
// 	})
// 	if err != nil {
// 		logging.Get().Err(err).Str("Filename", saveInfo.Filename).Str("FileMd5", saveInfo.FileMd5).Msg("MaliciousScan SendKafka")
// 		return err
// 	}
// 	logging.Get().Debug().Int("Data", len(saveInfo.Data)).Str("FileMd5", saveInfo.FileMd5).Msg("MaliciousScan SendKafka")
// 	return nil
// }
