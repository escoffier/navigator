package mozart

import (
	"context"
	"errors"

	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"

	"gitlab.com/security-rd/go-pkg/logging"
)

func (e *Engine) configToRegoQuery(stepName, stepCode string) (regoQuery rego.PreparedEvalQuery, err error) {
	ctx := context.Background()
	switch stepName {
	// 纯表达式
	case "checkExpression":
		regoQuery, err = rego.New(
			rego.Query(stepCode),
			rego.Function2(
				&rego.Function{
					Name: "CacheContext",
					Decl: types.NewFunction(types.Args(types.S, types.S), types.A),
				},
				CacheContext),
		).PrepareForEval(ctx)
	case "execExpression":
		regoQuery, err = rego.New(
			rego.Query(stepCode),
			rego.Function2(
				&rego.Function{
					Name: "CacheContext",
					Decl: types.NewFunction(types.Args(types.S, types.S), types.A),
				},
				CacheContext),
		).PrepareForEval(ctx)

	// 内置函数
	case "checkValue":
		regoQuery, err = rego.New(
			rego.Query(stepCode),
			rego.Function2(
				&rego.Function{
					Name: "CacheContext",
					Decl: types.NewFunction(types.Args(types.S, types.S), types.A),
				},
				CacheContext),
		).PrepareForEval(ctx)
	case "checkRelatedExists":
		regoQuery, err = rego.New(
			rego.Query(stepCode),
			rego.Function2(
				&rego.Function{
					Name: "CacheContext",
					Decl: types.NewFunction(types.Args(types.S, types.S), types.A),
				},
				CacheContext),
			rego.FunctionDyn(
				&rego.Function{
					Name: "ExistsInPeriod",
					Decl: types.NewFunction(types.Args(types.S, types.S, types.S, types.A, types.S), types.B),
				},
				e.ExistsInPeriod),
		).PrepareForEval(ctx)
	case "checkRelatedNotExists":
		regoQuery, err = rego.New(
			rego.Query(stepCode),
			rego.Function2(
				&rego.Function{
					Name: "CacheContext",
					Decl: types.NewFunction(types.Args(types.S, types.S), types.A),
				},
				CacheContext),
			rego.Function3(
				&rego.Function{
					Name: "NotExistsInPeriod",
					Decl: types.NewFunction(types.Args(types.S, types.S, types.S), types.A),
				},
				e.NotExistsInPeriod),
		).PrepareForEval(ctx)
	case "checkRuleRecentCount":
		regoQuery, err = rego.New(
			rego.Query(stepCode),
			rego.Function2(
				&rego.Function{
					Name: "CacheContext",
					Decl: types.NewFunction(types.Args(types.S, types.S), types.A),
				},
				CacheContext),
			rego.FunctionDyn(
				&rego.Function{
					Name: "RuleRecentCount",
					Decl: types.NewFunction(types.Args(types.S, types.S, types.N, types.S, types.N, types.S, types.S, types.S), types.B),
				},
				e.RuleRecentCount),
		).PrepareForEval(ctx)
	case "checkRegexMatch":
		regoQuery, err = rego.New(
			rego.Query(stepCode),
			rego.Function2(
				&rego.Function{
					Name: "CacheContext",
					Decl: types.NewFunction(types.Args(types.S, types.S), types.A),
				},
				CacheContext),
			rego.Function2(
				&rego.Function{
					Name: "CheckRegexMatch",
					Decl: types.NewFunction(types.Args(types.S, types.S), types.B),
				},
				e.CheckRegexMatch),
		).PrepareForEval(ctx)

	case "execDefineValue":
		regoQuery, err = rego.New(
			rego.Query(stepCode),
			rego.Function2(
				&rego.Function{
					Name: "makeValue",
					Decl: types.NewFunction(types.Args(types.S, types.S), types.A),
				},
				makeValue),
		).PrepareForEval(ctx)
	case "execGenerateSignal":
		regoQuery, err = rego.New(
			rego.Query(stepCode),
			rego.Function2(
				&rego.Function{
					Name: "CacheContext",
					Decl: types.NewFunction(types.Args(types.S, types.S), types.A),
				},
				CacheContext),
			rego.Function3(
				&rego.Function{
					Name: "generateAlertSignal",
					Decl: types.NewFunction(types.Args(types.A, types.A, types.S), types.A),
				},
				e.GenerateAlertSignal),
		).PrepareForEval(ctx)
	case "execSendPalace":
		regoQuery, err = rego.New(
			rego.Query(stepCode),
			rego.Function2(
				&rego.Function{
					Name: "CacheContext",
					Decl: types.NewFunction(types.Args(types.S, types.S), types.A),
				},
				CacheContext),
			rego.Function1(
				&rego.Function{
					Name: "sendSignalToPalace",
					Decl: types.NewFunction(types.Args(types.A), types.A),
				},
				e.SendSignalToPalace),
		).PrepareForEval(ctx)
	default:
		err = errors.New("no match step name")
		logging.Get().Error().Err(err).Str("stepName", stepName).Str("stepCode", stepCode).Msg("no match step name")
	}

	return
}
