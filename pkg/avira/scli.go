package avira

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/go-multierror"
	"gitlab.com/security-rd/go-pkg/logging"
	"k8s.io/apimachinery/pkg/util/wait"
)

const (
	defaultProductID = "14359"
)

type SavClient struct {
	ServerAddr   string   // server addr,e.g.tcp:127.0.0.1:9090
	serverSchema string   // tcp or unix
	serverUrl    string   // 127.0.0.1:9090
	conn         net.Conn // connection with server
	isConnectOk  bool     // true: connect ok
}

func (s *SavClient) GetProductID() string {
	value := os.Getenv("AVIRA_PRODUCTID")
	if len(value) == 0 {
		return defaultProductID
	}
	return value
}

// FIXME 测试该处可能一直卡死
func (s *SavClient) ScanFile(filePath string) ([]Malware, error) {
	logging.Get().Debug().Str("file", filePath).Msg("SavClient start scan")

	// send scan command
	err := s.send([]byte(fmt.Sprintf("SCAN %s", filePath)))
	if err != nil {
		logging.Get().Err(err).Str("file", filePath).Msg("SavClient failed to send scan command")
		return nil, err
	}

	// read response
	res, err := s.readScanResult()
	if err != nil {
		logging.Get().Err(err).Str("file", filePath).Msg("SavClient scan err")
		return res, err
	}

	logging.Get().Debug().Str("file", filePath).Int("malwareCnt", len(res)).Msg("SavClient scan end")
	return res, nil
}

// parseResponseWithMalware response format: 420 [fileA-in-archive[ --> fileB-in-fileA] <<< ]alert-name ; type ; english-text-message
func (s *SavClient) parseResponseWithMalware(line string) (*Malware, error) {
	arr := strings.Split(line, alertMessageDelimiter)
	if len(arr) != 3 {
		return nil, fmt.Errorf("line format err:%s", line)
	}

	// get malware realpath for archive
	innerPath := ""
	malwareName := ""
	arr2 := strings.Split(arr[0], innerPathDelimiter)
	if len(arr2) > 1 {
		innerPath = arr2[0]
		malwareName = arr2[1]
	} else {
		malwareName = arr[0]
	}
	m := &Malware{
		Name:              strings.TrimSpace(malwareName),
		Type:              strings.TrimSpace(arr[1]),
		Desc:              strings.TrimSpace(arr[2]),
		FilePathInArchive: innerPath,
	}
	return m, nil
}

func (s *SavClient) logDiffByCode(respCode int) error {
	var err error
	switch respCode {
	case SavApiRspCode100, SavApiRspCode199, SavApiRspCode401, SavApiRspCode404, SavApiRspCode450, SavApiRspCode499:
		// should not recv this code with "SCAN" command
		err = fmt.Errorf("should not recv this rsp code:%d", respCode)
	case SavApiRspCode200, SavApiRspCode210, SavApiRspCode319:
		// do nothing
	case SavApiRspCode220:
		// todo: should reconnect
		err = fmt.Errorf("connect timeout")
	case SavApiRspCode350:
		err = fmt.Errorf("unexpected error")
	case SavApiRspCode421, SavApiRspCode422, SavApiRspCode423, SavApiRspCode430:
		// do nothing
	case SavApiRspCode310, SavApiRspCode420:
		// do nothing
	default:
		err = fmt.Errorf("unsupported rsp code")
	}

	if err != nil {
		logging.Get().Err(err).Int("respCode", respCode).Msg("wrong rsp code")
	} else {
		logging.Get().Debug().Int("respCode", respCode).Msg("normal rsp code")
	}

	return err
}

func (s *SavClient) parseLine(line string) (int, string, error) {
	arr := strings.Split(line, messageDelimiter)
	if len(arr) < 2 {
		logging.Get().Error().Str("line", line).Msg("response line format err")
		return 0, "", fmt.Errorf("line formate err:%v", line)
	}

	respCode, err := strconv.Atoi(arr[0])
	if err != nil {
		logging.Get().Err(err).Msg("invalid rsp code")
		return 0, "", fmt.Errorf("invalide rsp code.%v", arr[0])
	}
	content := strings.Join(arr[1:], messageDelimiter)

	return respCode, content, nil
}

func (s *SavClient) readScanResult() ([]Malware, error) {
	var err *multierror.Error
	appendErr := func(newErr error) {
		err = multierror.Append(err, newErr)
	}

	stopChan := make(chan struct{})
	malwareRes := make([]Malware, 0)
	appendMalwareRes := func(m Malware) bool {
		exist := false
		for _, v := range malwareRes {
			if strings.TrimSpace(m.Name) == strings.TrimSpace(v.Name) {
				exist = true
				break
			}
		}
		if exist {
			// false: not append
			return false
		}
		malwareRes = append(malwareRes, m)
		return true
	}

	lastLine := ""
	totalRsp := ""
	wait.Until(func() {
		logging.Get().Debug().Str("lastLine", lastLine).Msg("before read rsp")

		// read response
		curRsp, err := s.readRsp()
		if err != nil {
			logging.Get().Err(err).Msg("failed to get response")
			appendErr(err)
			close(stopChan)
			return
		}

		// append last line
		totalRsp = lastLine + curRsp
		logging.Get().Debug().Str("curRsp", curRsp).Str("totalRsp", totalRsp).Msg("recv sav server rsp")

		// rsp with multi lines: <status-code> <data>\n (for UNIX)
		// e.g.310 LINUX/Xorddos.cona ; virus ; Contains detection pattern of the Linux virus LINUX/Xorddos.cona\n319 OK\n
		shouldFinish := false
		lines := strings.Split(totalRsp, "\n")
		lastLine = lines[len(lines)-1]
		for _, line := range lines[:len(lines)-1] {
			logging.Get().Debug().Str("line", line).Msg("rsp line")

			// parse line
			respCode, content, err := s.parseLine(line)
			if err != nil {
				logging.Get().Err(err).Msg("failed to parse line")
				appendErr(err)
				continue
			}

			// check response code
			if respCode == SavApiRspCode310 || respCode == SavApiRspCode420 {
				// need parse malware
				m, err := s.parseResponseWithMalware(content)
				if err != nil {
					// not quit,continue recv msg
					logging.Get().Err(err).Msg("rsp format err")
					appendErr(fmt.Errorf("rsp formate err:%s", content))
				} else {
					appendMalwareRes(*m)
				}
				continue
			} else if respCode == SavApiRspCode421 || respCode == SavApiRspCode422 || respCode == SavApiRspCode423 || respCode == SavApiRspCode430 {
				// not finish,continue process other line and read from server
				logging.Get().Debug().Int("code", respCode).Msg("continue do other lines and recv msg")
				continue
			} else {
				// other code should finish this process. just mark flag,continue handle other lines
				shouldFinish = true

				// log diff by code
				err = s.logDiffByCode(respCode)
				appendErr(err)
			}
		}

		if shouldFinish {
			logging.Get().Debug().Msg("SavClient finish this response")
			close(stopChan)
		}

	}, 1*time.Second, stopChan)

	return malwareRes, err.ErrorOrNil()
}

func (s *SavClient) readRsp() (string, error) {
	buf := make([]byte, 1024)
	n, err := s.conn.Read(buf)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

func (s *SavClient) ConnServer() error {
	logging.Get().Info().Msgf("SavClient start connect,%s,%s", s.serverSchema, s.serverUrl)
	conn, err := net.Dial(s.serverSchema, s.serverUrl)
	if err != nil {
		logging.Get().Err(err).Msg("connect failed")
		return err
	}
	s.conn = conn

	// read inform rsp.e.g.100 SAVAPI:4.0\n
	rsp, err := s.readRsp()
	if err != nil {
		return err
	}
	logging.Get().Info().Str("rsp", rsp).Msg("connect rsp")

	data := fmt.Sprintf("SET PRODUCT %s", s.GetProductID())
	err = s.send([]byte(data))
	if err != nil {
		return err
	}

	// read set product rsp.e.g.100 PRODUCT:13398\n
	rsp, err = s.readRsp()
	if err != nil {
		return err
	}
	logging.Get().Info().Str("rsp", rsp).Msg("set product id")

	return nil
}

func (s *SavClient) send(data []byte) error {
	_, err := s.conn.Write(append(data, '\n'))
	if err != nil {
		return err
	}
	return nil
}

func (s *SavClient) Close() error {
	err := s.send([]byte("QUIT"))
	if err != nil {
		// not quit.close anyway
		logging.Get().Err(err).Msg("failed to send quit msg to sav server")
	}
	return s.conn.Close()
}

func NewSavClient(serverAddr string) (*SavClient, error) {
	s := &SavClient{
		ServerAddr: serverAddr,
	}

	// a little check
	arr := strings.Split(s.ServerAddr, ":")
	if len(arr) < 2 {
		return nil, fmt.Errorf("wrong server addr format:%s", serverAddr)
	}
	s.serverSchema = arr[0]
	s.serverUrl = strings.Join(arr[1:], ":")
	logging.Get().Info().Str("schema", s.serverSchema).Str("url", s.serverUrl).Msg("NewSavClient")

	// connect to server
	if err := s.ConnServer(); err != nil {
		return nil, err
	}
	return s, nil
}
