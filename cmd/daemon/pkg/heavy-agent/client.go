package heavyagent

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"
	"k8s.io/apimachinery/pkg/util/wait"
)

const (
	moduleKey     = "module"
	moduleName    = "heavy-agent"
	messagePrefix = "#%% pre"
)

type ReConnectCB func() error

type Client struct {
	conn       net.Conn
	path       string
	cbs        []ReConnectCB
	mutex      sync.Mutex
	headerBuf  [eventHeaderLen]byte
	getReadBuf func(size uint32) []byte
	readBuf    []byte // cache for default getReadBuf
}

func NewClient(address string) (*Client, error) {
	var err error
	var conn net.Conn

	connected := make(chan struct{})
	wait.Until(func() {
		conn, err = net.Dial("tcp", address)
		if err == nil {
			logging.Get().Info().Msgf("connected to %s", address)
			close(connected)
			return
		}
		logging.Get().Err(err).Msgf("unable to dial socket (%s)", address)
	}, time.Second*3, connected)

	client := Client{conn: conn, path: address}
	client.getReadBuf = func(size uint32) []byte {
		if cap(client.readBuf) >= int(size) {
			return client.readBuf[:size]
		}
		client.readBuf = make([]byte, size)
		return client.readBuf
	}

	return &client, nil
}

func (cli *Client) GetConn() net.Conn {
	return cli.conn
}

func (cli *Client) ReConnect() error {
	cli.Stop()

	logging.Get().Info().Msgf("try to reconnect to %s", cli.path)

	conn, err := net.Dial("tcp", cli.path)
	if err != nil {
		return fmt.Errorf("unable to dial socket(%s): %w", cli.path, err)
	}

	logging.Get().Info().Msgf("reconnected to  %s", cli.path)
	cli.conn = conn

	go func() {
		for _, cb := range cli.cbs {
			cb()
		}
	}()

	logging.Get().Info().Msg("finish reconnection callback")
	return nil
}

func (cli *Client) Stop() {
	_ = cli.conn.Close()
}

func (cli *Client) Send(data []byte) error {
	logging.Get().Info().Int64("timestamp", time.Now().UnixMilli()).Msgf("try to send data: %s", string(data))
	cli.mutex.Lock()
	defer cli.mutex.Unlock()

	err := cli.conn.SetWriteDeadline(time.Now().Add(time.Second * 3))
	if err != nil {
		logging.Get().Err(err).Msg("set deadline for sending data")
	}

	logging.Get().Info().Int64("timestamp", time.Now().UnixMilli()).Msgf("send data: %s", string(data))
	var buf []byte
	buf = append(buf, []byte(messagePrefix)...)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(data)))
	buf = append(buf, data...)
	_, err = cli.conn.Write(buf)
	if err != nil {
		logging.Get().Err(err).Msgf("send data: %d", len(data))
		cli.ReConnect()
		return err
	}
	logging.Get().Info().Int64("timestamp", time.Now().UnixMilli()).Msgf("send data end %s", string(data))
	return nil
}

func (cli *Client) Receive() ([]byte, error) {
	cli.mutex.Lock()
	defer cli.mutex.Unlock()

	var data = make([]byte, 4096)
	// cli.conn.SetReadDeadline(time.Now().Add(time.Second * 10))
	// defer cli.conn.SetReadDeadline(time.Time{})
	nBytes, err := cli.conn.Read(data)
	logging.Get().Info().Msgf("receive data %s", string(data))
	if err != nil {
		logging.Get().Err(err).Msgf("receive data %s", string(data))
		if errors.Is(err, io.EOF) {
			err = cli.ReConnect()
		}
		return nil, err
	}
	//logging.Get().Info().Int64("timestamp", time.Now().UnixMilli()).Msgf("response len %d:, body: %s", nBytes, string(data[:nBytes]))
	return data[:nBytes], nil
}

// read resp only once
func (cli *Client) SendAndReceiveOnce(data []byte) ([]byte, error) {
	logging.Get().Info().Int64("timestamp", time.Now().UnixMilli()).Msgf("try to send data: %s", string(data))
	cli.mutex.Lock()
	defer cli.mutex.Unlock()

	err := cli.conn.SetDeadline(time.Now().Add(time.Second * 3))
	if err != nil {
		logging.Get().Err(err).Msg("set deadline for sending data")
	}

	logging.Get().Info().Int64("timestamp", time.Now().UnixMilli()).Msgf("send data: %s", string(data))
	var buf []byte
	buf = append(buf, []byte(messagePrefix)...)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(data)))
	buf = append(buf, data...)
	_, err = cli.conn.Write(buf)
	if err != nil {
		logging.Get().Err(err).Msgf("send data: %d", len(data))
		cli.ReConnect()
		return nil, err
	}
	logging.Get().Info().Int64("timestamp", time.Now().UnixMilli()).Msgf("send data end %s", string(data))

	var respData = make([]byte, 4096)
	nBytes, err := cli.conn.Read(respData)
	logging.Get().Info().Msgf("receive data %s", string(respData))
	if err != nil {
		logging.Get().Err(err).Msgf("receive data %s", string(respData))
		if errors.Is(err, io.EOF) {
			err = cli.ReConnect()
		}
		return nil, err
	}
	//logging.Get().Info().Int64("timestamp", time.Now().UnixMilli()).Msgf("response len %d:, body: %s", nBytes, string(data[:nBytes]))
	return respData[:nBytes], nil
}

func (cli *Client) SendAndReceive(data []byte) ([]byte, error) {
	logging.Get().Info().Int64("timestamp", time.Now().UnixMilli()).Msgf("try to send data: %s", string(data))
	cli.mutex.Lock()
	defer cli.mutex.Unlock()

	err := cli.conn.SetDeadline(time.Now().Add(time.Second * 3))
	if err != nil {
		logging.Get().Err(err).Msg("set deadline for sending data")
	}

	logging.Get().Info().Int64("timestamp", time.Now().UnixMilli()).Msgf("send data: %s", string(data))
	var buf []byte
	buf = append(buf, []byte(messagePrefix)...)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(data)))
	buf = append(buf, data...)
	_, err = cli.conn.Write(buf)
	if err != nil {
		logging.Get().Err(err).Msgf("send data: %d", len(data))
		cli.ReConnect()
		return nil, err
	}
	logging.Get().Info().Int64("timestamp", time.Now().UnixMilli()).Msgf("send data end %s", string(data))

	header, err := cli.readHeader()
	if err != nil {
		return nil, err
	}

	paylaod := cli.getReadBuf(header.Length)
	logging.Get().Info().Msgf("payload len: %d", header.Length)

	_, err = io.ReadFull(cli.conn, paylaod)
	if err != nil {
		return nil, err
	}
	logging.Get().Info().Msgf("payload read len: %d", header.Length)
	return paylaod, nil

	// var respData = make([]byte, 4096)
	// nBytes, err := cli.conn.Read(respData)
	// logging.Get().Info().Msgf("receive data %s", string(respData))
	// if err != nil {
	// 	logging.Get().Err(err).Msgf("receive data %s", string(respData))
	// 	if errors.Is(err, io.EOF) {
	// 		err = cli.ReConnect()
	// 	}
	// 	return nil, err
	// }
	//logging.Get().Info().Int64("timestamp", time.Now().UnixMilli()).Msgf("response len %d:, body: %s", nBytes, string(data[:nBytes]))
	// return respData[:nBytes], nil
}

// deprecated
func (cli *Client) ReceiveFormatData(v any) error {
	cli.mutex.Lock()
	defer cli.mutex.Unlock()

	var buf []byte
	var readPos int

	for {
		logging.Get().Debug().Msg("begine to read event data")
		var data = make([]byte, 40960)
		nBytes, err := cli.GetConn().Read(data)
		if err != nil {
			logging.Get().Err(err).Msg("read evevnt data err")
			// time.Sleep(time.Millisecond * 500)
			if errors.Is(err, io.EOF) {
				_ = cli.ReConnect()
			}
			return err
		}
		var message []byte
		if len(buf) > 0 {
			message = append(message, buf...)
			message = append(message, data...)
			buf = buf[:0]
		} else {
			message = append(message, data...)
		}

		logging.Get().Info().Str(moduleKey, moduleName).Msgf("received agent event: %v, length: %d", string(message[readPos:readPos+7]), nBytes)
		if nBytes > 0 {
			messageLen := len(message)
			// func() {
			// for {
			if messageLen < readPos+7 {
				// cache buf
				// buf = slices.Concat(buf, message)
				logging.Get().Info().Msgf("cache len: %d", len(buf))
				buf = append(buf, message...)
				// currentPos = currentPos + nBytes
				continue
			}
			pre := string(message[readPos : readPos+7])
			// logging.Get().Info().Str(moduleKey, moduleName).Msgf("readPos: %d, prefix: %v", readPos, message[readPos:(readPos+7)])

			var msgLen int32
			if pre == eventPrefix {
				if int(messageLen) < readPos+11 {
					buf = append(buf, message...)
					readPos = 0
					continue
				}

				l := binary.LittleEndian.Uint32(message[readPos+7 : readPos+11])
				msgLen = int32(l)
				logging.Get().Info().Msgf("msg len: %d, current len: %d", msgLen, messageLen)
				if messageLen < int(msgLen) {
					buf = append(buf, message...)
					readPos = 0
					continue
				}
			} else {
				logging.Get().Debug().Msg("skip invalid message header")
				return fmt.Errorf("invalid msg header")
				// skip invalid header
				// readPos = readPos + 1
				// nBytes = nBytes - 1
				// continue
			}
			// event := make(map[string]interface{})
			err = json.Unmarshal(message[readPos+11:readPos+int(msgLen)], v)
			if err != nil {
				logging.Get().Err(err).Msgf("unmarshal event, len : %d, value : %s", len(message), message[readPos+11:readPos+int(msgLen)+11])
				return err
			}
			return nil
		}
	}
}

func (cli *Client) readHeader() (EventHeader, error) {
	_, err := io.ReadFull(cli.conn, cli.headerBuf[:])
	if err != nil {
		return EventHeader{}, err
	}
	return EventHeader{
		Prefix: cli.headerBuf[:7],
		Length: binary.LittleEndian.Uint32(cli.headerBuf[7:11]),
	}, nil
}

func (cli *Client) SendAndReceiveMessage(data []byte, v any) error {
	respData, err := cli.SendAndReceive(data)
	if err != nil {
		return err
	}
	err = json.Unmarshal(respData, v)
	return err
}

func (cli *Client) ReceiveMessage(v any) error {
	header, err := cli.readHeader()
	if err != nil {
		return err
	}

	paylaod := cli.getReadBuf(header.Length)
	logging.Get().Info().Msgf("paylaod len: %d", header.Length)

	_, err = io.ReadFull(cli.conn, paylaod)
	if err != nil {
		return err
	}
	logging.Get().Info().Msgf("paylaod read len: %d", header.Length)
	err = json.Unmarshal(paylaod, v)
	if err != nil {
		return err
	}
	return nil
}

func (cli *Client) ReceiveData() ([]byte, error) {
	header, err := cli.readHeader()
	if err != nil {
		return nil, err
	}

	paylaod := cli.getReadBuf(header.Length)
	logging.Get().Info().Msgf("payload len: %d", header.Length)

	_, err = io.ReadFull(cli.conn, paylaod)
	if err != nil {
		return nil, err
	}
	logging.Get().Info().Msgf("payload read len: %d", header.Length)
	return paylaod, nil
}

func (cli *Client) AddConnectCallback(cb ReConnectCB) {
	cli.cbs = append(cli.cbs, cb)
}
