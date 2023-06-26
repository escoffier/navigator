package microseg

import (
	"gitlab.com/piccolo_su/vegeta/cmd/clustermanager/pkg/microseg/types"
	"k8s.io/client-go/tools/cache"
)

type store struct {
	storage cache.Indexer
}

func NewRuleStore() *store {
	storage := cache.NewIndexer(func(obj interface{}) (string, error) {
		rule := obj.(*types.NetwokPolicyRule)
		return string(rule.UID), nil
	}, cache.Indexers{"policy-index": func(obj interface{}) ([]string, error) {
		rule := obj.(*types.NetwokPolicyRule)
		return []string{rule.PolicyID}, nil
	}})

	return &store{storage: storage}
}

func NewPolicyStore() *store {
	storage := cache.NewIndexer(func(obj interface{}) (string, error) {
		policy := obj.(*types.NetwokPolicy)
		return policy.Name, nil
	}, cache.Indexers{
		// "label-index": func(obj interface{}) ([]string, error) {
		// 	policy := obj.(*types.NetwokPolicy)
		// 	// policy.
		// }
	})

	return &store{storage: storage}
}
