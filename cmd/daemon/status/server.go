package status

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	param "github.com/oceanicdev/chi-param"
	"gitlab.com/security-rd/go-pkg/logging"

	heavyagent "gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/heavy-agent"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/heavy-agent/pb"
)

var log = logging.Get().With().Str("module", "status").Logger()

const requestTimeout = 3 * time.Second

type Server struct {
	port uint16
	cli  *heavyagent.ControlClient
}

func NewServer(port uint16, cli *heavyagent.ControlClient) *Server {
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
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	resp, err := s.cli.DumpConfig(ctx, &pb.DumpConfigRequest{PolicyName: name})
	if err != nil {
		return nil, err
	}
	return json.Marshal(resp)
}

func (s *Server) SetAgentLogLevelReq(level int) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	resp, err := s.cli.SetLogLevel(ctx, &pb.SetLogLevelRequest{Level: int32(level)})
	if err != nil {
		return nil, err
	}
	return json.Marshal(resp)
}

func (s *Server) dumpAgentHeap(enable string) (*pb.StatusResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	resp, err := s.cli.DumpHeapProfile(ctx, &pb.DumpHeapProfileRequest{Enable: enable == "y"})
	if err != nil {
		return nil, err
	}
	if resp.GetStatus() != 0 {
		return nil, fmt.Errorf("agent err %d", resp.GetStatus())
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
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	resp, err := s.cli.DumpConnections(ctx, &pb.DumpConnectionsRequest{Limit: int32(limit)})
	if err != nil {
		return nil, err
	}
	return json.Marshal(resp)
}

func (s *Server) reset() error {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	resp, err := s.cli.ResetConfig(ctx, &pb.ResetConfigRequest{})
	if err != nil {
		return err
	}
	if resp.GetStatus() != 0 {
		return fmt.Errorf("agent err %d", resp.GetStatus())
	}
	return nil
}

func (s *Server) handleReset(w http.ResponseWriter, r *http.Request) {
	err := s.reset()
	if err != nil {
		log.Err(err).Msg("reset agent")
		w.WriteHeader(500)
		return
	}
	w.WriteHeader(200)
}
