package mozart

import (
	"context"
	"errors"

	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"

	"gitlab.com/security-rd/go-pkg/logging"
)

func (w *Worker) configToRegoQuery(stepName, stepCode string) (regoQuery rego.PreparedEvalQuery, err error) {
	ctx := context.Background()
	switch stepName {
	// 纯表达式
	case "checkExpression":
		regoQuery, err = rego.New(
			rego.Query(stepCode),
			rego.Function1(
				&rego.Function{
					Name: "CacheContext",
					Decl: types.NewFunction(types.Args(types.S), types.A),
				},
				w.CacheContext),
		).PrepareForEval(ctx)
	case "execExpression":
		regoQuery, err = rego.New(
			rego.Query(stepCode),
			rego.Function1(
				&rego.Function{
					Name: "CacheContext",
					Decl: types.NewFunction(types.Args(types.S), types.A),
				},
				w.CacheContext),
		).PrepareForEval(ctx)

	// 内置函数
	case "checkValue":
		regoQuery, err = rego.New(
			rego.Query(stepCode),
			rego.Function1(
				&rego.Function{
					Name: "CacheContext",
					Decl: types.NewFunction(types.Args(types.S), types.A),
				},
				w.CacheContext),
		).PrepareForEval(ctx)
	case "checkRelatedExists":
		regoQuery, err = rego.New(
			rego.Query(stepCode),
			rego.Function1(
				&rego.Function{
					Name: "CacheContext",
					Decl: types.NewFunction(types.Args(types.S), types.A),
				},
				w.CacheContext),
			rego.FunctionDyn(
				&rego.Function{
					Name: "ExistsInPeriod",
					Decl: types.NewFunction(types.Args(types.S, types.S, types.S, types.A, types.S), types.B),
				},
				w.ExistsInPeriod),
		).PrepareForEval(ctx)
	case "checkRelatedNotExists":
		regoQuery, err = rego.New(
			rego.Query(stepCode),
			rego.Function1(
				&rego.Function{
					Name: "CacheContext",
					Decl: types.NewFunction(types.Args(types.S), types.A),
				},
				w.CacheContext),
			rego.Function3(
				&rego.Function{
					Name: "NotExistsInPeriod",
					Decl: types.NewFunction(types.Args(types.S, types.S, types.S), types.A),
				},
				w.NotExistsInPeriod),
		).PrepareForEval(ctx)
	case "execGenerateSignal":
		regoQuery, err = rego.New(
			rego.Query(stepCode),
			rego.Function1(
				&rego.Function{
					Name: "CacheContext",
					Decl: types.NewFunction(types.Args(types.S), types.A),
				},
				w.CacheContext),
			rego.Function2(
				&rego.Function{
					Name: "generateAlertSignal",
					Decl: types.NewFunction(types.Args(types.A, types.A), types.A),
				},
				w.GenerateAlertSignal),
		).PrepareForEval(ctx)
	case "execSendPalace":
		regoQuery, err = rego.New(
			rego.Query(stepCode),
			rego.Function1(
				&rego.Function{
					Name: "CacheContext",
					Decl: types.NewFunction(types.Args(types.S), types.A),
				},
				w.CacheContext),
			rego.Function1(
				&rego.Function{
					Name: "sendSignalToPalace",
					Decl: types.NewFunction(types.Args(types.A), types.A),
				},
				w.SendSignalToPalace),
		).PrepareForEval(ctx)
	default:
		err = errors.New("no match step name")
		logging.Get().Error().Err(err).Str("stepName", stepName).Str("stepCode", stepCode).Msg("no match step name")
	}

	return
}
