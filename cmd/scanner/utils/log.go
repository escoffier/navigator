package scannerUtils

import (
	"context"

	"github.com/rs/zerolog"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
)

type LogEvent struct {
	Module    string
	Submodule string
	Ctx       context.Context
}

type LogEventOption func(*LogEvent)

func WithModule(value string) LogEventOption {
	return func(c *LogEvent) {
		c.Module = value
	}
}

func WithSubModule(value string) LogEventOption {
	return func(c *LogEvent) {
		c.Submodule = value
	}
}

func (vi *LogEvent) WithCtx(ctx context.Context) LogEventOption {
	return func(c *LogEvent) {
		c.Ctx = ctx
	}
}

func NewLogEvent(opt ...LogEventOption) *LogEvent {
	s := &LogEvent{}
	for i := range opt {
		op := opt[i]
		op(s)
	}
	return s
}

func (vi *LogEvent) Info() *zerolog.Event {
	ev := logging.Get().Info()
	if vi.Module != "" {
		ev = ev.Str(consts.LogModule, vi.Module)
	}
	if vi.Submodule != "" {
		ev = ev.Str(consts.LogSubModule, vi.Submodule)
	}
	return ev
}

func (vi *LogEvent) Repeat(key string) *zerolog.Event {

	return nil
}

func (vi *LogEvent) Debug() *zerolog.Event {
	ev := logging.Get().Debug()
	if vi.Module != "" {
		ev = ev.Str(consts.LogModule, vi.Module)
	}
	if vi.Submodule != "" {
		ev = ev.Str(consts.LogSubModule, vi.Submodule)
	}
	return ev
}

func (vi *LogEvent) Err(err error) *zerolog.Event {
	ev := logging.Get().Err(err)
	if vi.Module != "" {
		ev = ev.Str(consts.LogModule, vi.Module)
	}
	if vi.Submodule != "" {
		ev = ev.Str(consts.LogSubModule, vi.Submodule)
	}
	return ev
}

func (vi *LogEvent) Error() *zerolog.Event {
	ev := logging.Get().Error()
	if vi.Module != "" {
		ev = ev.Str(consts.LogModule, vi.Module)
	}
	if vi.Submodule != "" {
		ev = ev.Str(consts.LogSubModule, vi.Submodule)
	}
	return ev
}
