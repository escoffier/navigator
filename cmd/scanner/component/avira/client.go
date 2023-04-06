package avira

import (
	"fmt"
	"io/fs"
	"net"
	"path/filepath"

	// "runtime/debug"
	"strconv"
	"strings"

	// "sync"

	"gitlab.com/security-rd/go-pkg/logging"
)

var (
	socketAddr = "unix:/run/savapi/savapi.sock"
	// socketAddr = "tcp:127.0.0.1:9999"
	productId = "14359"
)

const (
	messageDelimiter      = " "
	alertMessageDelimiter = ";"
)

type proto struct {
	conn net.Conn
	// srvInfo map[string]string
}

func initProto(path, productId string) (*proto, error) {
	protoCli := &proto{}
	pathList := strings.Split(path, ":")
	if len(pathList) != 2 {
		return nil, fmt.Errorf("path format error")
	}

	if conn, err := net.Dial(pathList[0], strings.Join(pathList[1:], ":")); err != nil {
		logging.Get().Err(err).Msg("dial fail")
		return nil, err
	} else {
		protoCli.conn = conn
	}

	buf := make([]byte, 1024)
	if _, err := protoCli.conn.Read(buf); err != nil {
		logging.Get().Err(err).Msg("read conn fail")
		return nil, err
	}

	protoCli.send("SET PRODUCT " + productId)
	buf = make([]byte, 1024)
	protoCli.conn.Read(buf)
	logging.Get().Info().Msg("init proto success")
	return protoCli, nil
}

func (p *proto) send(data string) error {
	if _, err := p.conn.Write(append([]byte(data), '\n')); err != nil {
		logging.Get().Err(err).Msg("write conn fail")
		return err
	}

	return nil
}

type scanner struct {
	pCli *proto
	dirs map[string]struct{}
}

func NewAClient() (*scanner, error) {
	// return &scanner{
	// 	dirs: map[string]string{},
	// }, nil
	protoCli, err := initProto(socketAddr, productId)
	if err != nil {
		return nil, err
	}
	return &scanner{
		pCli: protoCli,
		dirs: make(map[string]struct{}),
	}, nil
}

func (sc *scanner) Scan(path string) ([]string, error) {
	err := sc.pCli.send("SCAN " + path)
	if err != nil {
		logging.Get().Err(err).Msg("send scan fail")
	}
	retAlerts := []string{}
	respCode := 0
	finish := false
	lastLine := ""
	for !finish {
		buf := make([]byte, 1024)
		_, err := sc.pCli.conn.Read(buf)
		if err != nil {
			logging.Get().Err(err).Msg("read scan fail")
			break
		}
		respData := string(buf)
		respData = strings.Trim(respData, "\x00")
		lines := strings.Split(respData, "\n")
		if len(lines) == 0 {
			logging.Get().Err(err).Msg("read lines fail")
			break
		}

		if len(lines) == 1 && respData[len(respData)-1] != '\n' {
			lastLine += lines[0]
			continue
		}
		for index, line := range lines[:len(lines)-1] {
			if index == 0 {
				line = lastLine + line
			}
			respList := strings.Split(line, messageDelimiter)
			if len(respList) == 0 {
				logging.Get().Err(err).Msg("read scan fail")
				break
			}

			respCode, err = strconv.Atoi(respList[0])
			if err != nil {
				logging.Get().Err(err).Msgf("read scan fail, line: %v(%v)", line, len(line))
				finish = true
				break
			}

			switch respCode {
			case 200:
				logging.Get().Debug().Msgf("scan file: %v, result: %v", path, line)
			case 310:
				// example: 310 LINUX/Xorddos.cona ; virus ; Contains detection pattern of the Linux virus LINUX/Xorddos.cona
				// example: 310 dota3.tar --> .rsync/a/kswapd0 <<< LINUX/BitCoinMiner.tfrvf ; virus ; Contains detection pattern of the Linux virus LINUX/BitCoinMiner.tfrvf

				logging.Get().Info().Msgf("Alert found %v", line)
				descList := strings.Split(line, alertMessageDelimiter)
				virusName := strings.Trim(descList[0], " ")
				descList = strings.Split(virusName, " ")
				virusName = descList[len(descList)-1]
				retAlerts = append(retAlerts, virusName)
			case 430:
				logging.Get().Trace().Msgf("Alert URL %v", line)

			default:
				logging.Get().Warn().Str("resp code", respList[0]).Msgf("scan file: %v, message: %v", path, line)
			}
			// is terminal?
			switch respCode {
			case 310:
			case 401:
			case 421:
			case 422:
			case 423:
			case 430:
			case 450:
			case 499:
				// Non-terminal, do nothing
				// continue
			default:
				finish = true
			}

		}

		lastLine = lines[len(lines)-1]
	}
	return retAlerts, nil
}

func (sc *scanner) Close() error {
	sc.finish()
	return nil
}
func (sc *scanner) finish() error {
	sc.pCli.send("QUIT")
	sc.pCli.conn.Close()
	return nil
}

func (sc *scanner) reset() error {
	sc.pCli.send("RESET")
	return nil
}

func (sc *scanner) changeDetectType() error {
	return nil
}

func (sc *scanner) filepathCollect(path string, di fs.DirEntry, err error) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	sc.dirs[abs] = struct{}{}
	return nil
}

func getScanFiles(path string, sc *scanner) error {
	err := filepath.WalkDir(path, sc.filepathCollect)
	return err
}

func ScanDir(path string) (map[string][]string, error) {
	scannerCli, err := NewAClient()
	if err != nil {
		return nil, err
	}
	retMap := make(map[string][]string)
	getScanFiles(path, scannerCli)
	logging.Get().Info().Msgf("avira scan files size: %v", len(scannerCli.dirs))

	for d, _ := range scannerCli.dirs {
		result, err := scannerCli.Scan(d)
		if err != nil {
			logging.Get().Err(err).Msgf("scan file %v fail", d)
		}
		if len(result) > 0 {
			retMap[d] = result
		}
	}
	scannerCli.finish()
	return retMap, nil
}

// func concurrentScan(dirs []string) {
// 	var wg sync.WaitGroup
// 	ch := make(chan struct{}, 10)
// 	for index, p := range dirs {
// 		wg.Add(1)
// 		ch <- struct{}{}
// 		go func(i int, path string) {
// 			defer wg.Done()
// 			defer func() {
// 				<-ch
// 			}()
// 			defer func() {
// 				if r := recover(); r != nil {
// 					logging.Get().Error().Msgf("Panic: %v. stack: %s", r, debug.Stack())
// 				}
// 			}()
// 			ScanDir(i, path)

// 		}(index, p)

// 	}
// 	wg.Wait()
// }
