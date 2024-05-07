package heavyagent

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"sync"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"
	"k8s.io/apimachinery/pkg/util/wait"
)

const (
	moduleKey  = "module"
	moduleName = "heavy-agent"
)

type ReConnectCB func() error

type Client struct {
	conn  *net.UnixConn
	path  string
	cbs   []ReConnectCB
	mutex sync.Mutex
}

func NewClient(address string) (*Client, error) {
	var stats fs.FileInfo
	var err error

	for i := 0; i < 10; i++ {
		stats, err = os.Stat(address)
		if err != nil {
			time.Sleep(time.Second * 2)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("could not stat socket address(%s): %w", address, err)
	}

	switch stats.Mode() {
	case 0770, 1770:
		return nil, fmt.Errorf("socket address(%s) had incorrect mode(%v), must be 0770", address, stats.Mode())
	}

	connected := make(chan struct{})
	var conn net.Conn
	wait.Until(func() {
		var err error
		conn, err = net.Dial("unix", address)
		if err == nil {
			logging.Get().Info().Msgf("connected to %s", address)
			close(connected)
			return
		}
		logging.Get().Err(err).Msgf("unable to dial socket (%s)", address)
	}, time.Second*3, connected)
	return &Client{conn: conn.(*net.UnixConn), path: address}, nil
}

func (cli *Client) GetConn() net.Conn {
	return cli.conn
}

func (cli *Client) ReConnect() error {
	stats, err := os.Stat(cli.path)
	if err != nil {
		return fmt.Errorf("could not stat socket address(%s): %w", cli.path, err)
	}

	switch stats.Mode() {
	case 0770, 1770:
		return fmt.Errorf("socket address(%s) had incorrect mode(%v), must be 0770", cli.path, stats.Mode())
	}

	conn, err := net.Dial("unix", cli.path)
	if err != nil {
		return fmt.Errorf("unable to dial socket(%s): %w", cli.path, err)
	}
	logging.Get().Info().Msgf("reconnected to uds %s", cli.path)
	cli.conn = conn.(*net.UnixConn)

	go func() {
		for _, cb := range cli.cbs {
			cb()
		}
	}()

	return nil
}

func (cli *Client) Stop() {
	cli.conn.Close()
}

func (cli *Client) Send(data []byte) error {
	cli.mutex.Lock()
	defer cli.mutex.Unlock()

	cli.conn.SetWriteDeadline(time.Now().Add(time.Second * 3))
	defer cli.conn.SetWriteDeadline(time.Time{})

	logging.Get().Info().Int64("timestamp", time.Now().UnixMilli()).Msgf("send data: %s", string(data))
	_, err := cli.conn.Write(data)
	if err != nil {
		logging.Get().Err(err).Msgf("send data: %d", len(data))
		cli.ReConnect()
		return err
	}
	return nil
}

func (cli *Client) Receive() ([]byte, error) {
	cli.mutex.Lock()
	defer cli.mutex.Unlock()

	var data = make([]byte, 2000000)
	cli.conn.SetReadDeadline(time.Now().Add(time.Second * 10))
	defer cli.conn.SetReadDeadline(time.Time{})
	nBytes, err := cli.conn.Read(data)
	if err != nil {
		logging.Get().Err(err).Msgf("receive data %s", string(data))
		if errors.Is(err, io.EOF) {
			err = cli.ReConnect()
		}
		return nil, err
	}
	logging.Get().Info().Int64("timestamp", time.Now().UnixMilli()).Msgf("response len %d:, body: %s", nBytes, string(data[:nBytes]))
	return data[:nBytes], nil
}

func (cli *Client) AddConnectCallback(cb ReConnectCB) {
	cli.cbs = append(cli.cbs, cb)
}
