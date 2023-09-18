package configs

import (
	"fmt"
	"hash/fnv"
	"strings"
)

func dbRuleToRule(dbRule TensorMicrosegRule, IDMap map[uint32]uint32, newMap map[uint32]CommonMicroSegObject) (Rule, error) {
	action, ok := actionToDto[dbRule.Action]
	if !ok {
		return Rule{}, fmt.Errorf("invalid dbRule.Action: %d", dbRule.Action)
	}
	direction, ok := directionToDto[dbRule.Direction]
	if !ok {
		return Rule{}, fmt.Errorf("invalid dbRule.Direction: %d", dbRule.Direction)
	}
	protocol, ok := protocolTypeToDto[dbRule.Protocol]
	if !ok {
		return Rule{}, fmt.Errorf("invalid dbRule.Protocol: %d", dbRule.Protocol)
	}

	rule := Rule{
		Direction: direction,
		Action:    action,
		Protocol:  protocol,
		Ports:     dbRule.Ports,
		Comment:   dbRule.Comment,
		IsSegRule: dbRule.IsSegRule,
	}

	if direction == Ingress {
		srcType := microTypeToDto[dbRule.SrcType]
		srcId := IDMap[dbRule.SrcID] // 将新uuid写入
		switch srcType {
		case Segment:
			rule.SrcSegment = SuggestionSegment{
				Name:      newMap[srcId].Name,
				Namespace: newMap[srcId].Namespace,
				Cluster:   newMap[srcId].Cluster,
			}
		case Resource:
			rule.SrcResource = SuggestionResource{
				Name:      newMap[srcId].Name,
				Kind:      newMap[srcId].Kind,
				Namespace: newMap[srcId].Namespace,
				Cluster:   newMap[srcId].Cluster,
			}
		case IPBlock:
			rule.SrcIPBlock = dbRule.SrcIPBlock
		case Namespace:
			rule.SrcNamespace = SuggestionNamespace{
				Name:    newMap[srcId].Name,
				Cluster: newMap[srcId].Cluster,
			}
		case Tenant:
			rule.SrcTenant = SuggestionTenant{
				Cluster: newMap[srcId].Cluster,
				Name:    newMap[srcId].Name,
			}
		case Nsgrp:
			rule.SrcNsgrp = SuggestionNsgrp{
				Name:    newMap[srcId].Name,
				Cluster: newMap[srcId].Cluster,
			}
		}
		rule.SrcType = srcType
		rule.SrcId = srcId
	} else {
		dstType := microTypeToDto[dbRule.DstType]
		dstId := IDMap[dbRule.DstID] // 将新uuid写入
		switch dstType {
		case Segment:
			rule.DstSegment = SuggestionSegment{
				Name:      newMap[dstId].Name,
				Namespace: newMap[dstId].Namespace,
				Cluster:   newMap[dstId].Cluster,
			}
		case Resource:
			rule.DstResource = SuggestionResource{
				Name:      newMap[dstId].Name,
				Kind:      newMap[dstId].Kind,
				Namespace: newMap[dstId].Namespace,
				Cluster:   newMap[dstId].Cluster,
			}
		case IPBlock:
			rule.DstIPBlock = dbRule.DstIPBlock
		case Namespace:
			rule.DstNamespace = SuggestionNamespace{
				Name:    newMap[dstId].Name,
				Cluster: newMap[dstId].Cluster,
			}
		case Tenant:
			rule.DstTenant = SuggestionTenant{
				Cluster: newMap[dstId].Cluster,
				Name:    newMap[dstId].Name,
			}
		case Nsgrp:
			rule.SrcNsgrp = SuggestionNsgrp{
				Name:    newMap[dstId].Name,
				Cluster: newMap[dstId].Cluster,
			}
		}
		rule.DstType = dstType
		rule.DstId = dstId
	}

	return rule, nil
}

func GenID(strs ...string) uint32 {
	s := strings.Join(strs, ",")
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return h.Sum32()
}
