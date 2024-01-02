package hm

import (
	"archive/tar"
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	dockerarchive "github.com/docker/docker/pkg/archive"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"k8s.io/apimachinery/pkg/util/rand"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	imagesecTypes "gitlab.com/piccolo_su/vegeta/pkg/types/imagesec"
)

type ScanHM struct {
	BinCnt      int64
	EnginBack   []*EnginMeta
	WG          sync.Locker // 主要用于获取引擎
	HmRootPath  string      // /opt/webshell/hm
	ScanTimeout int64       // 单位：秒
	Log         *scannerUtils.LogEvent
}

type EnginMeta struct {
	Using       bool // 是否在使用中
	EnginNO     int64
	HmRootPath  string // /opt/webshell/hm
	BinFilename string // hm 的二制制执行文件
	DbFilename  string // hm 扫描后会把结果果保存在当前目录的data.db文件中,这是一个sqlite文件
	CsvFilename string // hm 扫描后会把结果果保存在当前目录的result.csv文件中,这是一个csv文件
	Log         *scannerUtils.LogEvent
}

type SingleHMSrv struct {
	ScanHM *ScanHM
	WG     sync.Locker
}

// 这样才保险
func init() {
	singleHmMeta = &SingleHMSrv{
		ScanHM: nil,
		WG:     &sync.Mutex{},
	}
}

var singleHmMeta *SingleHMSrv

// 单例
func NewScanHM(opts ...Option) (*ScanHM, error) {
	singleHmMeta.WG.Lock()
	defer singleHmMeta.WG.Unlock()

	if singleHmMeta.ScanHM != nil {
		return singleHmMeta.ScanHM, nil
	}
	s := &ScanHM{
		HmRootPath:  "/opt/webshell/hm",
		ScanTimeout: 10 * 60,
		WG:          &sync.Mutex{},
		BinCnt:      consts.DefaultHmEnginCnt,
		Log: scannerUtils.NewLogEvent(
			scannerUtils.WithSubModule("ScanHM"),
			scannerUtils.WithModule(consts.ModuleImageScan),
		),
	}
	cnt, err := strconv.Atoi(os.Getenv("HM_ENGIN_CNT"))
	if err == nil && cnt > 0 {
		s.BinCnt = int64(cnt)
	}

	for i := range opts {
		opts[i](s)
	}

	if err := s.createHmBack(context.Background(), int(s.BinCnt)); err != nil {
		return nil, err
	}

	singleHmMeta.ScanHM = s

	return singleHmMeta.ScanHM, nil
}

func (s *ScanHM) createHmBack(ctx context.Context, n int) error {
	toCtx, cancelFunc := context.WithTimeout(ctx, time.Minute*10)
	defer cancelFunc()

	for i := 0; i < n; i++ {
		// 因为要拼接，所有 s.HmRootPath不能是/opt/webshell/hm/ 后面不能有斜杠
		str := fmt.Sprintf("%s%d", s.HmRootPath, i)
		cmd := exec.CommandContext(toCtx, "cp", "-r", s.HmRootPath, str)
		err := cmd.Run()
		if err != nil {
			s.Log.Err(err).Msg("CreateHmBack error")
			return err
		}
		en := &EnginMeta{
			EnginNO:     int64(i),
			HmRootPath:  str,
			BinFilename: fmt.Sprintf("%s/%s", str, "hm"),
			DbFilename:  fmt.Sprintf("%s/%s", str, "data.db"),
			CsvFilename: fmt.Sprintf("%s/%s", str, "result.csv"),
			Log: scannerUtils.NewLogEvent(
				scannerUtils.WithSubModule("ScanHM"),
				scannerUtils.WithModule(consts.ModuleImageScan),
			),
		}
		s.EnginBack = append(s.EnginBack, en)
	}
	s.Log.Info().Int("hmCnt", n).Msg("createHmBack")
	return nil
}

// 获取引擎
func (s *ScanHM) GetHMEngin(ctx context.Context) (*EnginMeta, error) {
	start := time.Now().Unix()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		s.WG.Lock()
		for i := range s.EnginBack {
			en := s.EnginBack[i]
			if !en.Using {
				s.EnginBack[i].Using = true
				en.Using = true
				s.WG.Unlock()
				s.Log.Debug().Interface("engin", en).Msg("GetHMEngin")
				return en, nil
			}
		}
		s.WG.Unlock()
		s.Log.Debug().Msg("GetHMEngin not get hm engin and wait next")
		if time.Now().Unix()-start > s.ScanTimeout {
			err := fmt.Errorf("get hm engin timeout")
			s.Log.Err(err).Msg("GetHMEngin get engin timeout")
			return nil, err
		}
		ticker.Reset(time.Duration(rand.Int63nRange(1000, 3000)) * time.Millisecond)
		<-ticker.C
	}
}

// 归还引擎
func (s *ScanHM) BackHMEngin(ctx context.Context, eng *EnginMeta) {
	s.Log.Debug().Interface("engin", eng).Msg("BackHMEngin start")

	s.WG.Lock()
	defer s.WG.Unlock()
	for i := range s.EnginBack {
		en := s.EnginBack[i]
		if en.EnginNO == eng.EnginNO {
			s.EnginBack[i].Using = false
			en.Using = false
		}
	}
	s.Log.Debug().Interface("engin", eng).Msg("BackHMEngin end")
}

func (s *ScanHM) ImageScan(ctx context.Context, pre *imagesecTypes.PrepareScan) []imagesecTypes.ScanJobResult {
	s.Log.Info().Str(consts.SubtaskLogName, pre.Subtask.LogStr()).Str(consts.ScanJobLogName, "ScanHM").Msg("scan job start")
	defer s.Log.Info().Str(consts.SubtaskLogName, pre.Subtask.LogStr()).Str(consts.ScanJobLogName, "ScanHM").Msg("scan job end")
	result := make([]imagesecTypes.ScanJobResult, 0)
	out := make(chan imagesecTypes.ScanJobResult)
	defer close(out)

	for i := range pre.Layers {
		ly := pre.Layers[i]
		go func(tx context.Context, ly *imagesecTypes.ImageLayer, prep *imagesecTypes.PrepareScan, out chan imagesecTypes.ScanJobResult) {
			s.scanJob(ctx, ly, prep, out)
		}(ctx, ly, pre, out)
	}

	for i := 0; i < len(pre.Layers); i++ {
		res := <-out
		result = append(result, res)
	}

	uidMap, gidMap, _ := s.GetPasswdAndGroup(ctx, pre)

	for i := range result {
		for j := range result[i].Webshell {
			ws := result[i].Webshell[j]
			// 容器中可能没有 passwd 和 group 文件，且这里也不要求一定有值，所以没有判错
			uid, _ := scannerUtils.FileUID(ws.Filename)
			uname := uidMap[uid].Username
			gid, _ := scannerUtils.FileUID(ws.Filename)
			gname := gidMap[gid].Name
			ws.Mod = fmt.Sprintf("%s %s %s", ws.Mod, uname, gname)
			result[i].Webshell[j] = ws
		}
	}

	return result
}

func (s *ScanHM) scanJob(ctx context.Context, ly *imagesecTypes.ImageLayer, prep *imagesecTypes.PrepareScan, out chan imagesecTypes.ScanJobResult) {

	res := imagesecTypes.ScanJobResult{
		Layer: ly.Digest,
		Issue: imagesecModel.WebshellCacheData,
	}

	if prep.Subtask.WebshellCache.In(ly.Digest) {
		res.InCache = true
		s.Log.Debug().Str("subtask", prep.Subtask.LogStr()).Str("layer", ly.Digest).
			Str("Issue", imagesecModel.WebshellCacheData).Msg("scan layer data in cache")
		out <- res
		return
	}

	webshell, err := s.scanWebshell(ctx, ly)
	if err != nil {
		res.Errors = append(res.Errors, err)
	} else {
		res.Webshell = append(res.Webshell, webshell...)
	}
	for j := range res.Webshell {
		fi := ly.ContainerFilename(res.Webshell[j].Filename)
		stat, err := os.Stat(fi)
		if err != nil {
			continue
		}
		res.Webshell[j].Mod = stat.Mode().String()
	}
	res.Scanned = true
	out <- res
}

func (s *ScanHM) scanWebshell(ctx context.Context, ly *imagesecTypes.ImageLayer) ([]imagesecTypes.HmWebshell, error) {
	res := make([]imagesecTypes.HmWebshell, 0)

	s.Log.Debug().Str("scanPath", ly.LayerFilePath).Msg("Scan")

	en, err := s.GetHMEngin(ctx)

	if err != nil {
		s.Log.Info().Str("scanPath", ly.LayerFilePath).Msg("Scan GetHMEngin")
		return res, err
	}

	defer func() { s.BackHMEngin(ctx, en) }()
	defer func() { _ = en.removeWhDb(ctx, en.DbFilename) }()
	defer func() { _ = en.removeWhDb(ctx, en.CsvFilename) }()

	s.Log.Debug().Interface("EnginMeta", en).Msg("Scan GetHMEngin")

	err = en.cmdScan(ctx, ly.LayerFilePath, consts.DefaultScanTimeout)
	if err != nil {
		s.Log.Info().Str("scanPath", ly.LayerFilePath).Msg("Scan cmdScan")
		return res, err
	}

	pre, err := en.parseWhDb(ctx, en.DbFilename)
	if err != nil {
		s.Log.Info().Str("scanPath", ly.LayerFilePath).Msg("Scan parseWhDb")
		return nil, err
	}
	for i := range pre {
		pre[i].Layer = ly.Digest
	}

	return pre, nil
}

func (s *EnginMeta) parseWhDb(ctx context.Context, dbFilename string) ([]imagesecTypes.HmWebshell, error) {
	res := make([]imagesecTypes.HmWebshell, 0)

	if !scannerUtils.FileExist(dbFilename) {
		return res, fmt.Errorf("not find db file:%s", dbFilename)
	}

	db, err := gorm.Open(sqlite.Open(dbFilename), &gorm.Config{})
	if err != nil {
		s.Log.Err(err).Msg("open hm sqlite error")
		return nil, err
	}
	resB := make([]imagesecModel.CertainWebshell, 0)

	err = db.Model(&imagesecModel.CertainWebshell{}).Select("*").Find(&resB).Error
	if err != nil {
		s.Log.Err(err).Msg("get hm tbl_b error")
		return nil, err
	}
	resS := make([]imagesecModel.MaybeWebshell, 0)

	err = db.Model(&imagesecModel.MaybeWebshell{}).Select("*").Find(&resS).Error
	if err != nil {
		s.Log.Err(err).Msg("get hm tbl_s error")
		return nil, err
	}

	for _, wbb := range resB {
		fileSize, _ := scannerUtils.FileSize(wbb.Filepath)
		wb := imagesecTypes.HmWebshell{
			Filename:    wbb.Filepath,
			Size:        fileSize,
			MD5:         wbb.Md5Hash,
			Code:        wbb.MaliciousData,
			RiskLevel:   imagesecModel.WebshellRiskLevelCertain,
			Description: wbb.Description,
		}
		res = append(res, wb)
	}

	for _, wbb := range resS {
		fileSize, _ := scannerUtils.FileSize(wbb.Filepath)
		wb := imagesecTypes.HmWebshell{
			Filename:    wbb.Filepath,
			MD5:         wbb.Md5Hash,
			Size:        fileSize,
			Code:        wbb.MaliciousData,
			RiskLevel:   imagesecModel.WebshellRiskLevelMaybe,
			Description: wbb.Description,
		}
		res = append(res, wb)
	}

	return res, nil
}

func (s *EnginMeta) removeWhDb(ctx context.Context, dbFilename string) error {
	if !scannerUtils.FileExist(dbFilename) {
		return nil
	}

	return os.RemoveAll(dbFilename)
}

func (s *EnginMeta) cmdScan(ctx context.Context, scanPath string, to int64) error {
	// 每一次扫描都会在hm 扫描器所在的目录下生成  data.db文件，这个文件是一个sqlite数据文件
	timeout, cancelFunc := context.WithTimeout(ctx, time.Minute*time.Duration(to))
	defer cancelFunc()

	if scannerUtils.FileExist(s.DbFilename) {
		// 先删除上一次扫描的结果文件
		if err := os.Remove(s.DbFilename); err != nil {
			return fmt.Errorf("can not remore pre scan db")
		}
	}
	cmd := exec.CommandContext(timeout, s.BinFilename, "scan", scanPath)
	_, err := cmd.CombinedOutput()
	if err != nil {
		_ = os.Remove(s.DbFilename)
		return err
	}
	return nil
}

func (s *ScanHM) GetPasswdAndGroup(ctx context.Context, prep *imagesecTypes.PrepareScan) (map[int64]imagesecModel.EtcPasswdUser, map[int64]imagesecModel.EtcGroupUser, error) {
	passwd := make(map[int64]imagesecModel.EtcPasswdUser)
	gp := make(map[int64]imagesecModel.EtcGroupUser)

	if prep == nil || prep.TaskRootDir == "" {
		return passwd, gp, nil
	}

	var (
		pass  string
		group string
	)

	_ = filepath.Walk(prep.TaskRootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if strings.HasSuffix(path, "etc/passwd") {
			pass = path
		}

		if strings.HasSuffix(path, "etc/group") {
			group = path
		}
		return nil
	})

	passwd, _ = scannerUtils.ParseEtcPasswd(pass)
	gp, _ = scannerUtils.ParseEtcGroup(group)

	return passwd, gp, nil
}

// 从tar 包中获取
func (s *ScanHM) getPasswdAndGroup(ctx context.Context, ly *imagesecTypes.ImageLayer) (map[int64]imagesecModel.EtcPasswdUser, map[int64]imagesecModel.EtcGroupUser, error) {
	passwd := make(map[int64]imagesecModel.EtcPasswdUser)
	gp := make(map[int64]imagesecModel.EtcGroupUser)

	file, err := os.Open(ly.OriginalTarFile)
	if err != nil {
		return nil, nil, err
	}
	// 不能使用自带的包直接解压，一定得有这一步
	decompressStreamReader, err := dockerarchive.DecompressStream(file)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = decompressStreamReader.Close() }()
	tarReader := tar.NewReader(decompressStreamReader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		fi := header.FileInfo().Name()
		if strings.HasSuffix(fi, "etc/passwd") {
			if etcPasswd, err := ParseEtcPasswd(tarReader); err == nil {
				passwd = etcPasswd
			}
			if etcPasswd, err := ParseEtcGroup(tarReader); err == nil {
				gp = etcPasswd
			}
		}
	}

	return passwd, gp, nil
}

func (s *ScanHM) GetPasswdAndGroup2(ctx context.Context, prepare *imagesecTypes.PrepareScan) (map[int64]imagesecModel.EtcPasswdUser, map[int64]imagesecModel.EtcGroupUser, error) {
	passwd := make(map[int64]imagesecModel.EtcPasswdUser)
	gp := make(map[int64]imagesecModel.EtcGroupUser)

	for i := range prepare.Layers {
		ly := prepare.Layers[i]
		ps, gro, _ := s.getPasswdAndGroup(ctx, ly)
		if len(ps) > 0 {
			passwd = ps
		}
		if len(gro) > 0 {
			gp = gro
		}
	}

	return passwd, gp, nil
}

func ParseEtcPasswd(file io.Reader) (map[int64]imagesecModel.EtcPasswdUser, error) {
	ans := make(map[int64]imagesecModel.EtcPasswdUser)
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

func ParseEtcGroup(file io.Reader) (map[int64]imagesecModel.EtcGroupUser, error) {
	ans := make(map[int64]imagesecModel.EtcGroupUser)
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
