package aviraengin

type Option func(srv *AviraSrv)

func WithClientPollCnt(cnt int) Option {
	return func(srv *AviraSrv) {
		srv.ClientPollCnt = cnt
	}
}

func WithScanTimeout(to int64) Option {
	return func(srv *AviraSrv) {
		srv.SingeFileTimeout = to
	}
}

func WithMaxSingeFileSize(to int64) Option {
	return func(srv *AviraSrv) {
		srv.MaxSingeFileSize = to
	}
}

func WithServerAddr(addr string) Option {
	return func(srv *AviraSrv) {
		srv.ServerAddr = addr
	}
}
