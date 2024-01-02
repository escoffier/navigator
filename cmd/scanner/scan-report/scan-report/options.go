package scanreport

import (
	"crypto/tls"
	"time"

	"gopkg.in/gomail.v2"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store/adaptStore"
)

type Option func(srv *ScanReportSrv)

func WithDB(dao adaptStore.ScanReportInterface) Option {
	return func(srv *ScanReportSrv) {
		srv.dao = dao
	}
}

func WithVulnDal(dao adaptStore.VulnDalInterface) Option {
	return func(srv *ScanReportSrv) {
		srv.vulnDal = dao
	}
}

func WithInternal(interval time.Duration) Option {
	return func(srv *ScanReportSrv) {
		srv.Interval = interval
	}
}

func WithBatchSize(batchSize int) Option {
	return func(srv *ScanReportSrv) {
		srv.batchSize = batchSize
	}
}

func WithEmailDialer(host string, port int, username, password string) Option {
	dial := gomail.NewDialer(host, port, username, password)
	dial.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	return func(srv *ScanReportSrv) {
		srv.email = dial
	}
}
