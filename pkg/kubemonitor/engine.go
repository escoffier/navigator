package kubemonitor

import (
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
)

type KubernetesAPI interface {
	GetClusterRole(name string) (*rbacv1.ClusterRole, bool)
	GetRole(name, namespace string) (*rbacv1.Role, bool)
}

type Engine struct {
	riskyRoleRules []*RiskyRoleItem
	k8sAPI         KubernetesAPI
	storage        KubeStorage
}

func NewEngine(rules []*RiskyRoleItem, api KubernetesAPI, storage KubeStorage) *Engine {
	return &Engine{
		riskyRoleRules: rules,
		k8sAPI:         api,
		storage:        storage,
	}
}

func isContainedInSlice(target string, sl []string) bool {
	for _, item := range sl {
		if target == item {
			return true
		}
	}
	return false
}

func (e *Engine) areRulesContainOtherRules(sourceRoleName, namespace string, roleRules []rbacv1.PolicyRule, riskyRules []Rule) bool {
	if len(roleRules) == 0 || len(riskyRules) == 0 {
		return false
	}

	matched := 0
	for _, riskRule := range riskyRules {
		for _, roleRule := range roleRules {
			if isRisky := e.isRuleContainsRiskyRule(sourceRoleName, namespace, roleRule, riskRule); isRisky {
				matched++
				if matched == len(riskyRules) {
					return true
				}
			}
		}
	}
	return false
}

func (e *Engine) isRuleContainsRiskyRule(sourceRoleName, namespace string, roleRule rbacv1.PolicyRule, riskyRule Rule) bool {
	isContains := true
	isBindVerbFound := false
	isRoleResourceFound := false
	/*
			Optional: uncomment and shift everything bellow till the 'return' to add any rules that have "*" in their verbs or resources.
		    currently it is being handled in risky_roles.yaml partially
		    if (source_rule.verbs is not None and "*" not in source_rule.verbs) and (source_rule.resources is not None and "*" not in source_rule.resources)
	*/
	for _, verb := range riskyRule.Verbs {
		if !isContainedInSlice(verb, roleRule.Verbs) {
			isContains = false
			break
		}

		if strings.ToLower(verb) == "bind" {
			isBindVerbFound = true
		}
	}

	if isContains && len(roleRule.Resources) > 0 {
		for _, riskyRes := range riskyRule.Resources {
			if !isContainedInSlice(riskyRes, roleRule.Resources) {
				isContains = false
				break
			}
			lowerRes := strings.ToLower(riskyRes)
			if lowerRes == "roles" || lowerRes == "clusterroles" {
				isRoleResourceFound = true
			}
		}

		if isContains && len(riskyRule.ResourceNames) > 0 {
			if isBindVerbFound && isRoleResourceFound {
				if risky, err := e.isRiskyResourceNameExist(sourceRoleName, namespace, roleRule.ResourceNames); err == nil && risky {
					isContains = true
				}
			}
		}
	} else {
		return false
	}

	return isContains
}

func (e *Engine) isRiskyResourceNameExist(roleName, namespace string, resourceNames []string) (bool, error) {
	for _, resName := range resourceNames {
		// prevent cycles
		if resName != roleName {
			var role *rbacv1.Role
			if len(namespace) > 0 {
				role, _ = e.k8sAPI.GetRole(resName, namespace)
				if role != nil {
					isRisky, _ := e.IsRiskyRole(role)
					if isRisky {
						return true, nil
					}
				}
			}
			if role == nil {
				clusterRole, _ := e.k8sAPI.GetClusterRole(resName)
				if clusterRole != nil {
					isRisky, _ := e.IsRiskyClusterRole(clusterRole)
					if isRisky {
						return true, nil
					}
				}
			}
		}
	}
	return false, nil
}

func (e *Engine) IsRiskyRole(role *rbacv1.Role) (bool, []*RiskyRoleItem) {
	matchedRiskyRules := make([]*RiskyRoleItem, 0, 1)
	risky := false
	for _, item := range e.riskyRoleRules {
		if e.areRulesContainOtherRules(role.Name, role.Namespace, role.Rules, item.Rules) {
			risky = true
			matchedRiskyRules = append(matchedRiskyRules, item)
		}
	}
	return risky, matchedRiskyRules
}

func (e *Engine) IsRiskyClusterRole(role *rbacv1.ClusterRole) (bool, []*RiskyRoleItem) {
	matchedRiskyRules := make([]*RiskyRoleItem, 0, 1)
	risky := false
	for _, item := range e.riskyRoleRules {
		if e.areRulesContainOtherRules(role.Name, "", role.Rules, item.Rules) {
			risky = true
			matchedRiskyRules = append(matchedRiskyRules, item)
		}
	}
	return risky, matchedRiskyRules
}
