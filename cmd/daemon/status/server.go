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
	mux.HandleFunc("/debug/agent/heapdump", s.handleDumpAgentHeap)

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
	// config := &AgentConfig{
	// 	UUID: uuid.NewString(),
	// 	Pids: []string{"123", "456"},
	// }
	w.Header().Set("Content-Type", "application/json")
	// data, _ := json.Marshal(config)
	resp, err := s.dumpAgentConfig()
	if err != nil {
		log.Err(err).Msg("dump config")
		w.WriteHeader(500)
		return
	}

	// data, _ := json.Marshal(resp)
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

func (s *Server) dumpAgentConfig() ([]byte, error) {
	req := ConfigDumpReq{
		UUID:        uuid.NewString(),
		MessageType: 10,
	}
	data, err := json.Marshal(&req)
	if err != nil {
		return nil, err
	}

	err = s.cli.Send(data)
	if err != nil {
		return nil, err
	}

	respData, err := s.cli.Receive()
	if err != nil {
		return nil, err
	}

	log.Debug().Msgf("received %d bytes response", len(respData))

	// resp, err := s.receiveResponse()
	// if err != nil {
	// 	return nil, err
	// }
	// if resp.Status != 0 {
	// 	return nil, fmt.Errorf("agent err %d", resp.Status)
	// }
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

	err = s.cli.Send(data)
	if err != nil {
		return nil, err
	}

	resp, err := s.receiveResponse()
	if err != nil {
		return nil, err
	}
	if resp.Status != 0 {
		return nil, fmt.Errorf("agent err %d", resp.Status)
	}
	return resp, nil
}

func (s *Server) receiveResponse() (*Response, error) {
	data, err := s.cli.Receive()
	if err != nil {
		return nil, err
	}

	log.Debug().Msgf("received %d bytes response", len(data))
	var resp = &Response{}
	if len(data) > 0 {
		log.Debug().Msgf("response: %s", string(data))
		err = json.Unmarshal(data, resp)
		if err != nil {
			return nil, err
		}
	}
	return resp, nil
}
