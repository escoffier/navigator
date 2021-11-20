package scan_report

import (
	"context"
	"fmt"
	"runtime"
	"runtime/debug"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/compress"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	scanreport "gitlab.com/piccolo_su/vegeta/pkg/model/scan-report"
	"gitlab.com/piccolo_su/vegeta/pkg/util"

	"github.com/pkg/errors"
	"gopkg.in/gomail.v2"
	"gorm.io/gorm"
)

var Host = "https://console.tensosecurity.cn"

const format = "2006-01-02 15:04:05 MST"
const contentFormat = `<div>已为您成功生成一份报告：</div>
<div>报告类型: %s</div>
<div>报告名称: %s</div>
<div>报告周期: %s - %s</div>
<div>平台链接: %s/#/image-scanning/recent-scan?reportId=%d&ctab=4</div>`

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
		logging.GetLogger().Error().Msgf("email login error: %v", err)
	}

	return srv
}

func (s *ScanReportSrv) Run() error {
	tick := time.NewTicker(s.interval)
	defer tick.Stop()
	for {
		logging.GetLogger().Info().Msg("start scan job")
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
		logging.GetLogger().Info().Msgf(
			"run task, name:%s, type: %s, start: %d, end: %d",
			v.TensorScanReportTasks.Name,
			v.TensorScanReportTasks.Type,
			v.StartTimeStamp,
			v.EndTimeStamp,
		)

		s.handleSubTask(ctx, v)
	}
}

func (s *ScanReportSrv) handleSubTask(ctx context.Context, v *scanreport.TensorScanReportSubTasks) {
	defer func() {
		if e := recover(); e != nil {
			logging.GetLogger().Error().Msgf(
				"scanner report execute failed, err: %v, subtask: %d, stack: %s",
				e,
				v.ID,
				debug.Stack(),
			)
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

	logging.GetLogger().Info().Msgf(
		"mark current task is doing success, name:%s, type: %s, start: %d, end: %d",
		v.TensorScanReportTasks.Name,
		v.TensorScanReportTasks.Type,
		v.StartTimeStamp,
		v.EndTimeStamp,
	)

	// 读取数据
	result, err := s.getImagesInfo(ctx, v)
	if err != nil {
		logging.GetLogger().
			Err(err).
			Msgf("get scanner report result failed, id: %d", v.ID)
		_ = s.dao.UpdateSubTaskStatus(ctx, v.ID, scanreport.SubTasksStatusFailed)
		return
	}

	logging.GetLogger().Info().Msgf(
		"get scanner report result success, name:%s, type: %s, start: %d, end: %d",
		v.TensorScanReportTasks.Name,
		v.TensorScanReportTasks.Type,
		v.StartTimeStamp,
		v.EndTimeStamp,
	)

	data, err := result.Marshal()
	if err != nil {
		logging.GetLogger().Err(err).
			Msgf("marshal scan report data failed, id: %d", v.ID)
		_ = s.dao.UpdateSubTaskStatus(ctx, v.ID, scanreport.SubTasksStatusFailed)
		return
	}

	logging.GetLogger().Info().Msgf(
		"marshal scan report data success, name:%s, type: %s, start: %d, end: %d",
		v.TensorScanReportTasks.Name,
		v.TensorScanReportTasks.Type,
		v.StartTimeStamp,
		v.EndTimeStamp,
	)

	result = nil
	// 压缩数据
	data1, err := compress.ZlipCompress(data)
	if err != nil {
		logging.GetLogger().Err(err).
			Msgf("compress scan report data failed, id: %d", v.ID)
		_ = s.dao.UpdateSubTaskStatus(ctx, v.ID, scanreport.SubTasksStatusFailed)
		return
	}

	logging.GetLogger().Info().Msgf(
		"compress scan report data success, name:%s, type: %s, start: %d, end: %d",
		v.TensorScanReportTasks.Name,
		v.TensorScanReportTasks.Type,
		v.StartTimeStamp,
		v.EndTimeStamp,
	)

	//nolint:ineffassign
	data = nil

	logging.GetLogger().Info().Msgf(
		"report<%s>, time：%d-%d, generate successfully，size: %.2f",
		v.TensorScanReportTasks.Name,
		v.StartTimeStamp,
		v.EndTimeStamp,
		float64(len(data1))/1024,
	)

	// 存储数据
	err = s.dao.SaveScanReportFile(ctx, v, data1)
	if err != nil {
		logging.GetLogger().Err(err).
			Msgf("save scan report data failed, id: %d", v.ID)
		_ = s.dao.UpdateSubTaskStatus(ctx, v.ID, scanreport.SubTasksStatusFailed)
		return
	}

	logging.GetLogger().Info().Msgf(
		"save scan report data success, name:%s, type: %s, start: %d, end: %d",
		v.TensorScanReportTasks.Name,
		v.TensorScanReportTasks.Type,
		v.StartTimeStamp,
		v.EndTimeStamp,
	)

	// 发送邮件
	err = s.sendEmails(ctx, v)
	if err != nil {
		logging.GetLogger().Err(err).Msgf(
			"report<%s>, time：%d-%d, emails send failed",
			v.TensorScanReportTasks.Name,
			v.StartTimeStamp,
			v.EndTimeStamp,
		)
	} else {
		logging.GetLogger().Info().Msgf(
			"report<%s>, time：%d-%d, emails send success",
			v.TensorScanReportTasks.Name,
			v.StartTimeStamp,
			v.EndTimeStamp,
		)
	}

	//nolint:ineffassign
	data1 = nil
	runtime.GC()
}

func (s *ScanReportSrv) sendEmails(_ context.Context, data *scanreport.TensorScanReportSubTasks) error {
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
		//nolint:ineffassign
		imageInfo = nil // for gc
		runtime.GC()    // gc manual
	}

	result := resultBuilder.GetResult()
	resultBuilder = nil
	runtime.GC()

	return result, nil
}

func (s *ScanReportSrv) checkEmail() error {
	f, err := s.email.Dial()
	if err != nil {
		return errors.Wrap(err, "can't connect to email server")
	}
	_ = f.Close()
	return nil
}
