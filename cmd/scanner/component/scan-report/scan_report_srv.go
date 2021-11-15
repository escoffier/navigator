package scan_report

import (
	"context"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/rs/zerolog/log"
	"gorm.io/gorm"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/compress"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	scanreport "gitlab.com/piccolo_su/vegeta/pkg/model/scan-report"
	"gitlab.com/piccolo_su/vegeta/pkg/util"

	"github.com/pkg/errors"
	"gopkg.in/gomail.v2"
)

var Host = "console.tensosecurity.cn"

const format = "2006-01-02 15:04:05 MST"
const contentFormat = `<div>已为您成功生成一份报告：</div>
<div>报告类型: %s</div>
<div>报告名称: %s</div>
<div>报告周期: %s - %s</div>
<div>平台链接: https://%s/#/image-scanning/recent-scan?reportId=%d&ctab=4</div>` // todo

type ScanReportSrv struct {
	dao       store.ScanReportInterface
	interval  time.Duration
	batchSize int
	email     *gomail.Dialer
}

func NewScanReportSrv(options ...Option) *ScanReportSrv {
	var srv = &ScanReportSrv{}

	for _, v := range options {
		v(srv)
	}

	if err := srv.checkEmail(); err != nil {
		log.Fatal().Msgf("email login error: %v", err)
	}

	return srv
}

func (s *ScanReportSrv) Run() error {
	tick := time.NewTicker(s.interval)
	defer tick.Stop()
	for {
		go s.run()
		<-tick.C
	}
}

func (s *ScanReportSrv) run() {

	now := time.Now().In(util.CSTSh)
	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	// 获取可以执行的任务
	tasks, err := s.dao.GetCurrentSubTask(ctx, now)
	if err != nil {
		logging.GetLogger().Error().Msgf("scanner report execute failed, get subtask error: %v", err)
		return
	}

	// 循环遍历可执行的任务
	for _, v := range tasks {
		s.handleSubTask(ctx, v)
	}
}

func (s *ScanReportSrv) handleSubTask(ctx context.Context, v *scanreport.TensorScanReportSubTasks) {
	defer func() {
		if e := recover(); e != nil {
			logging.GetLogger().Error().Msgf("scanner report execute failed, err: %v, subtask: %d, stack: %s", e, v.ID, debug.Stack())
		}
	}()

	if v.TensorScanReportTasks == nil {
		return
	}

	// 修改任务的状态
	err := s.dao.UpdateSubTaskStatusWithRunning(ctx, v)
	if err != nil {
		logging.GetLogger().
			Err(err).
			Msgf("scanner report execute failed, mark current task is doing failed, id: %d", v.ID)
		_ = s.dao.UpdateSubTaskStatus(ctx, v.ID, scanreport.SubTasksStatusFailed)
		return
	}

	// 读取数据
	result, err := s.getImagesInfo(ctx, v)
	if err != nil {
		logging.GetLogger().
			Err(err).
			Msgf("get scanner report result failed, id: %d", v.ID)
		_ = s.dao.UpdateSubTaskStatus(ctx, v.ID, scanreport.SubTasksStatusFailed)
		return
	}

	data, err := result.Marshal()
	if err != nil {
		logging.GetLogger().Err(err).
			Msgf("marshal scan report date failed, id: %d", v.ID)
		_ = s.dao.UpdateSubTaskStatus(ctx, v.ID, scanreport.SubTasksStatusFailed)
		return
	}

	// 压缩数据
	data, err = compress.ZlipCompress(data)
	if err != nil {
		logging.GetLogger().Err(err).
			Msgf("compress scan report date failed, id: %d", v.ID)
		_ = s.dao.UpdateSubTaskStatus(ctx, v.ID, scanreport.SubTasksStatusFailed)
		return
	}

	// 存储数据
	err = s.dao.SaveScanReportFile(ctx, v, data)
	if err != nil {
		logging.GetLogger().Err(err).
			Msgf("save scan report date failed, id: %d", v.ID)
		_ = s.dao.UpdateSubTaskStatus(ctx, v.ID, scanreport.SubTasksStatusFailed)
		return
	}

	// 发送邮件
	err = s.sendEmails(ctx, v)
	if err != nil {
		logging.GetLogger().Err(err).Msgf("报告<%s>, 时间：%d-%d, 发送失败", v.TensorScanReportTasks.Name, v.StartTimeStamp, v.EndTimeStamp)
	} else {
		logging.GetLogger().Info().Msgf("报告<%s>, 时间：%d-%d, 发送成功", v.TensorScanReportTasks.Name, v.StartTimeStamp, v.EndTimeStamp)
	}
}

func (s *ScanReportSrv) sendEmails(ctx context.Context, data *scanreport.TensorScanReportSubTasks) error {
	var content string
	var (
		start = time.Unix(0, data.StartTimeStamp*int64(time.Millisecond)).In(util.CSTSh).Format(format)
		end   = time.Unix(0, data.EndTimeStamp*int64(time.Millisecond)).In(util.CSTSh).Format(format)
	)

	var t string

	switch data.TensorScanReportTasks.Type {
	case scanreport.TensorScanReportTypeWeek:
		t = "周报"
	case scanreport.TensorScanReportTypeMonth:
		t = "月报"
	case scanreport.TensorScanReportTypeCustomize:
		t = "自定义报告"
	default:
		return fmt.Errorf("know report type: %d", data.TensorScanReportTasks.Type)
	}
	content = fmt.Sprintf(contentFormat, t, data.TensorScanReportTasks.Name, start, end, Host, data.TensorScanReportTasks.ID)

	m := gomail.NewMessage()
	m.SetHeader("From", m.FormatAddress(s.email.Username, ""))
	m.SetHeader("To", data.TensorScanReportTasks.Emails...)
	m.SetHeader("Subject", "镜像报告提醒")
	m.SetBody("text/html", content)

	return s.email.DialAndSend(m)
}

// 获取镜像数据
func (s *ScanReportSrv) getImagesInfo(ctx context.Context, data *scanreport.TensorScanReportSubTasks) (*scanreport.ScanReportResult, error) {
	resultBuilder := scanreport.NewScanReportResultBuilder(data.TensorScanReportTasks.ContentTypeEnum)
	resultBuilder.
		SetStartTime(data.StartTimeStamp).
		SetEndTime(data.EndTimeStamp).
		SetName(data.TensorScanReportTasks.Name).
		SetTpye(int64(data.TensorScanReportTasks.Type)).
		SetContentType(data.TensorScanReportTasks.ContentTypes)

	var offset int

	for {
		imageInfo, err := s.dao.GetImagesByTask(ctx, s.batchSize, offset, data)
		if err != nil {
			logging.GetLogger().Err(err).Msgf("生成报告时获取image info失败, task: %v, offset: %d", data.TensorScanReportTasks.Name, offset)

			if errors.Is(err, gorm.ErrRecordNotFound) {
				break
			}

			return nil, err
		}

		resultBuilder.BuildByImagesInfo(imageInfo)

		if len(imageInfo) < s.batchSize {
			break
		}

		offset += s.batchSize
	}

	return resultBuilder.GetResult(), nil
}

func (s *ScanReportSrv) checkEmail() error {
	f, err := s.email.Dial()
	if err != nil {
		return errors.Wrap(err, "can't connect to email server")
	}
	_ = f.Close()
	return nil
}
