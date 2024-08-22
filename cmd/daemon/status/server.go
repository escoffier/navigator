package status

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	"github.com/google/uuid"
	param "github.com/oceanicdev/chi-param"
	heavyagent "gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/heavy-agent"
	"gitlab.com/security-rd/go-pkg/logging"
)

var log = logging.Get().With().Str("module", "status").Logger()

type Server struct {
	port uint16
	cli  *heavyagent.Client
}

type AgentConfig struct {
	UUID string `json:"uuid"`
	Pids []string
}

type HeapDumpReq struct {
	UUID        string `json:"uuid"`
	MessageType int    `json:"msg_type"`
	Enable      string `json:"enable"`
}

type ConfigDumpReq struct {
	UUID        string `json:"uuid"`
	MessageType int    `json:"msg_type"`
	PolicyName  string `json:"policy_name"`
}

type LogLevelConfig struct {
	Level       int `json:"level"`
	MessageType int `json:"msg_type"`
}

type ConnDumpReq struct {
	UUID        string `json:"uuid"`
	MessageType int    `json:"msg_type"`
	Limit       int    `json:"limit"`
}

type Reset struct {
	UUID        string `json:"uuid"`
	MessageType int    `json:"msg_type"`
}

type Response struct {
	UUID   string `json:"uuid"`
	Status int    `json:"status"`
}

func NewServer(port uint16, cli *heavyagent.Client) *Server {
	return &Server{
		port: port,
		cli:  cli,
	}
}

func (s *Server) Run() {
	mux := http.NewServeMux()

	mux.HandleFunc("/debug/agent/config", s.handleDumpAgentConfig)
	mux.HandleFunc("/debug/agent/log", s.SetAgentLogLevel)
	mux.HandleFunc("/debug/agent/heapdump", s.handleDumpAgentHeap)
	mux.HandleFunc("/debug/agent/connections", s.handleDumpAgentConn)
	mux.HandleFunc("/debug/agent/reset", s.handleReset)

	go func() {
		l, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
		if err != nil {
			log.Err(err).Msg("listening on port")
			return
		}

		http.Serve(l, mux)
	}()
}

func (s *Server) handleDumpAgentConfig(w http.ResponseWriter, r *http.Request) {
	name, _ := param.QueryString(r, "name")

	w.Header().Set("Content-Type", "application/json")
	resp, err := s.dumpAgentConfig(name)
	if err != nil {
		log.Err(err).Msg("dump config")
		w.WriteHeader(500)
		return
	}

	w.Write(resp)
}

func (s *Server) SetAgentLogLevel(w http.ResponseWriter, r *http.Request) {
	level, _ := param.QueryInt(r, "level")
	/*print debug log*/
	log.Info().Msgf("agent log level : %+v", level)

	w.Header().Set("Content-Type", "application/json")

	resp, err := s.SetAgentLogLevelReq(level)
	if err != nil {
		log.Err(err).Msg("dump config")
		w.WriteHeader(500)
		return
	}

	w.Write(resp)
}

func (s *Server) handleDumpAgentHeap(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	enable, _ := param.QueryString(r, "enable")
	if enable != "y" && enable != "n" {
		log.Error().Msg("invalid param")
		w.WriteHeader(500)
		return
	}
	resp, err := s.dumpAgentHeap(enable)
	if err != nil {
		log.Err(err).Msg("dump heap")
		w.WriteHeader(500)
		return
	}

	data, _ := json.Marshal(resp)
	w.Write(data)
}

func (s *Server) dumpAgentConfig(name string) ([]byte, error) {
	req := ConfigDumpReq{
		UUID:        uuid.NewString(),
		PolicyName:  name,
		MessageType: 10,
	}
	data, err := json.Marshal(&req)
	if err != nil {
		return nil, err
	}
	// err = s.cli.Send(data)
	// if err != nil {
	// 	return nil, err
	// }

	// respData, err := s.cli.ReceiveData()
	// if err != nil {
	// 	return nil, err
	// }

	respData, err := s.cli.SendAndReceive(data)
	if err != nil {
		return nil, err
	}
	//log.Debug().Msgf("received %d bytes response", len(respData))
	return respData, nil
}

func (s *Server) SetAgentLogLevelReq(level int) ([]byte, error) {
	req := LogLevelConfig{
		Level:       level,
		MessageType: 14,
	}
	data, err := json.Marshal(&req)
	if err != nil {
		return nil, err
	}
	// err = s.cli.Send(data)
	// if err != nil {
	// 	return nil, err
	// }

	// respData, err := s.cli.Receive()
	// if err != nil {
	// 	return nil, err
	// }

	respData, err := s.cli.SendAndReceive(data)
	if err != nil {
		return nil, err
	}
	//log.Debug().Msgf("received %d bytes response", len(respData))
	return respData, nil
}

func (s *Server) dumpAgentHeap(enable string) (*Response, error) {
	req := HeapDumpReq{
		UUID:        uuid.NewString(),
		MessageType: 9,
		Enable:      enable,
	}
	data, err := json.Marshal(&req)
	if err != nil {
		return nil, err
	}
	// err = s.cli.Send(data)
	// if err != nil {
	// 	return nil, err
	// }

	// resp, err := s.receiveResponse()
	// if err != nil {
	// 	return nil, err
	// }
	respData, err := s.cli.SendAndReceive(data)
	if err != nil {
		return nil, err
	}
	var resp = &Response{}
	err = json.Unmarshal(respData, resp)
	if err != nil {
		return nil, err
	}
	if resp.Status != 0 {
		return nil, fmt.Errorf("agent err %d", resp.Status)
	}
	return resp, nil
}

func (s *Server) handleDumpAgentConn(w http.ResponseWriter, r *http.Request) {
	limit, _ := param.QueryInt(r, "limit")
	if limit == 0 {
		limit = 20
	}
	resp, err := s.dumpAgentConn(limit)
	if err != nil {
		log.Err(err).Msg("dump connection")
		w.WriteHeader(500)
		return
	}

	w.Write(resp)
}

func (s *Server) dumpAgentConn(limit int) ([]byte, error) {
	req := ConnDumpReq{
		UUID:        uuid.NewString(),
		MessageType: 11,
	}
	req.Limit = limit
	data, err := json.Marshal(&req)
	if err != nil {
		return nil, err
	}
	// err = s.cli.Send(data)
	// if err != nil {
	// 	return nil, err
	// }

	// respData, err := s.cli.Receive()
	// if err != nil {
	// 	return nil, err
	// }
	respData, err := s.cli.SendAndReceive(data)
	if err != nil {
		return nil, err
	}
	var resp = &Response{}
	err = json.Unmarshal(respData, resp)
	if err != nil {
		return nil, err
	}
	//log.Debug().Msgf("received %d bytes response", len(respData))

	return respData, nil
}

func (s *Server) reset() error {
	req := Reset{
		UUID:        uuid.NewString(),
		MessageType: 12,
	}
	data, err := json.Marshal(&req)
	if err != nil {
		return err
	}
	// err = s.cli.Send(data)
	// if err != nil {
	// 	return err
	// }

	// resp, err := s.receiveResponse()
	// if err != nil {
	// 	return err
	// }

	respData, err := s.cli.SendAndReceive(data)
	if err != nil {
		return err
	}
	var resp = &Response{}
	err = json.Unmarshal(respData, resp)
	if err != nil {
		return err
	}
	if resp.Status != 0 {
		return fmt.Errorf("agent err %d", resp.Status)
	}
	return nil
}

// func (s *Server) receiveResponse() (*Response, error) {
// 	data, err := s.cli.Receive()
// 	if err != nil {
// 		return nil, err
// 	}

// 	log.Debug().Msgf("received %d bytes response", len(data))
// 	var resp = &Response{}
// 	if len(data) > 0 {
// 		log.Debug().Msgf("response: %s", string(data))
// 		err = json.Unmarshal(data, resp)
// 		if err != nil {
// 			return nil, err
// 		}
// 	}
// 	return resp, nil
// }

func (s *Server) handleReset(w http.ResponseWriter, r *http.Request) {
	err := s.reset()
	if err != nil {
		log.Err(err).Msg("reset agent")
		w.WriteHeader(500)
		return
	}
	w.WriteHeader(200)
}
