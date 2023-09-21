package microseg

import "gitlab.com/security-rd/go-pkg/logging"

type EventProcessor struct {
	cli PolicyClient
}

func (p *EventProcessor) Run() {
	var event = make([]byte, 4096)
	for {
		nBytes, err := p.cli.GetConn().Read(event)
		if err != nil {
			logging.Get().Err(err).Msg("read evevnt data err: ")
			continue
		}
		if nBytes > 0 {
			logging.Get().Debug().Str(moduleKey, moduleName).Msgf("received dp event: %v", string(event))
		}
	}

}

func NewEventProcessor(cli PolicyClient) *EventProcessor {
	return &EventProcessor{
		cli: cli,
	}
}
