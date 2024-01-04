package heavyagent

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"
	"k8s.io/apimachinery/pkg/util/wait"
)

const (
	moduleKey  = "module"
	moduleName = "heavy-agent"
)

type ReConnectCB func()

type Client struct {
	conn *net.UnixConn
	path string
	cbs  []ReConnectCB
}

func NewClient(address string) (*Client, error) {
	var stats fs.FileInfo
	var err error

	for i := 0; i < 10; i++ {
		stats, err = os.Stat(address)
		if err != nil {
			time.Sleep(time.Second * 5)
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
	for _, cb := range cli.cbs {
		cb()
	}

	// return cli.controller.ReSyncAllPolicy()
	return nil
}

func (cli *Client) Stop() {
	cli.conn.Close()
}

func (cli *Client) Send(data []byte) error {
	cli.GetConn().SetWriteDeadline(time.Now().Add(time.Second * 3))
	logging.Get().Info().Str(moduleKey, moduleName).Msgf("send data: %s", string(data))
	// cli.writeDeadline = time.Time{}
	_, err := cli.GetConn().Write(data)
	if err != nil {
		cli.ReConnect()
		return err
	}
	return nil
}

func (cli *Client) Receive() ([]byte, error) {
	var data = make([]byte, 4096)
	nBytes, err := cli.GetConn().Read(data)
	if err != nil {
		if errors.Is(err, io.EOF) {
			err = cli.ReConnect()
		}
		return nil, err
	}
	logging.Get().Debug().Str(moduleKey, moduleName).Msgf("received %d bytes response", nBytes)
	logging.Get().Info().Str(moduleKey, moduleName).Msgf("response: %s", string(data))
	return data[:nBytes], nil
}

func (cli *Client) AddReConnectCallback(cb ReConnectCB) {
	cli.cbs = append(cli.cbs, cb)
}
