package status

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	"gitlab.com/security-rd/go-pkg/logging"
)

var log = logging.Get().With().Str("module", "status").Logger()

type Server struct {
	port uint16
}

type AgentConfig struct {
	Pids []string
}

func NewServer(port uint16) *Server {
	return &Server{
		port: port,
	}
}

func (s *Server) Run() {
	mux := http.NewServeMux()

	mux.HandleFunc("/debug/agent/config", s.handleDumpAgentConfig)

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
	config := &AgentConfig{
		Pids: []string{"123", "456"},
	}
	w.Header().Set("Content-Type", "application/json")
	data, _ := json.Marshal(config)
	w.Write(data)
}
