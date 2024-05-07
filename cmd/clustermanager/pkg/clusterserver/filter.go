package clusterserver

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/model"
	"gorm.io/gorm"
	corev1 "k8s.io/api/core/v1"
)

const (
	ServiceIpIndex = "ServiceIp"
	PodIpIndex     = "PodIp"
)

type MicroSegLogFilter struct {
	IsFilterService bool
	db              *databases.RDBInstance
}

func (p *MicroSegLogFilter) QueryResourceType(dataType MicroType, data string) string {
	switch dataType {
	case Resource:
		var res []model.TensorMicrosegResource
		err := p.db.Get().Model(model.TensorMicrosegResource{}).Scan(res).Error
		if err != nil && err != gorm.ErrRecordNotFound {
			logging.Get().Error().Msgf("scan resource information failed, %+v", err)
			return data
		}

		for i := 0; i < len(res); i++ {
			value := &res[i]
			if value.Name == data {
				if len(value.SegmentName) != 0 {
					return value.SegmentName
				} else {
					return data
				}
			}
		}

		return data
	case IPBlock:
		var ips []IPGroup
		err := p.db.Get().Model(IPGroup{}).Scan(ips).Error
		if err != nil {
			logging.Get().Error().Msgf("scan ip group information failed, %+v", err)
			return "unknown"
		}

		ipValue := net.ParseIP(data)
		for i := 0; i < len(ips); i++ {
			ipStr := strings.Split(ips[i].IpSet, ",")
			for _, ipAddr := range ipStr {
				cidr := strings.Split(ipAddr, "/")
				if len(cidr) == 1 {
					ipAddr = ipAddr + "/32"
				}
				_, ipNet, _ := net.ParseCIDR(ipAddr)
				if ipNet.Contains(ipValue) {
					return ips[i].Name
				}
			}
		}
	}
	return "unknown"
}

func (p *MicroSegLogFilter) FindRuleDto(dataType int, id uint32) (string, error) {
	var ObjName string
	// case model.Ingress:
	switch dataType {
	case Resource:
		res := &model.TensorMicrosegResource{}
		err := p.db.Get().First(res, "id = ?", id).Error
		if err != nil {
			return "", fmt.Errorf("get workload by id %d faile, %+v", id, err)
		}
		ObjName = res.SegmentName
	case Segment:
		seg := &TensorMicrosegSegment{}
		err := p.db.Get().First(seg, "id = ?", id).Error
		if err != nil {
			return "", fmt.Errorf("get segment by id %d faile, %+v", id, err)
		}
		ObjName = seg.Name
	case IPBlock:
		ig := &IPGroup{}
		err := p.db.Get().First(ig, "id = ?", id).Error
		if err != nil {
			return "", fmt.Errorf("get tenant by id %d faile, %+v", id, err)
		}
		ObjName = ig.Name
	case Nsgrp:
		nsgrp := &TensorMicrosegNsgrp{}
		err := p.db.Get().First(nsgrp, "id = ?", id).Error
		if err != nil {
			return "", fmt.Errorf("get namespace group by id %d faile, %+v", id, err)
		}
		ObjName = nsgrp.Name
	}

	if len(ObjName) == 0 {
		return "", fmt.Errorf("get policy name failed")
	}

	return ObjName, nil
}

func (cs *MicroSegLogFilter) GetPolicy(id int) (string, string, error) {
	var modelRule TensorMicrosegRule

	err := cs.db.Get().Model(&TensorMicrosegRule{}).Where("id = ?", id).First(&modelRule).Error
	if err != nil {
		return "", "", err
	}

	srcObj, err := cs.FindRuleDto(modelRule.SrcType, modelRule.SrcID)
	if err != nil {
		return "", "", fmt.Errorf("get policy source object name failed, %+v", err)
	}

	dstObj, err := cs.FindRuleDto(modelRule.DstType, modelRule.DstID)
	if err != nil {
		return "", "", fmt.Errorf("get policy dest object name failed, %+v", err)
	}

	return srcObj, dstObj, nil
}

func (cs *ClusterServer) GetPodByIp(ip string) (*PodResData, error) {
	objs, err := cs.Factory.Core().V1().Pods().Informer().GetIndexer().ByIndex(PodIpIndex, ip)
	if err != nil {
		return nil, err
	}

	if len(objs) == 0 {
		return nil, fmt.Errorf("pod not found")
	}

	pod := objs[0].(*corev1.Pod)
	res, kind := util.GetOwnerOfPod(pod)

	tensorPod := &PodResData{
		Namespace: pod.Namespace,
		KindName:  kind,
		PodName:   pod.Name,
		Resource:  res,
	}

	return tensorPod, nil
}

func (cs *ClusterServer) GetServiceResByIp(ip string) (string, string, string, error) {
	objs, err := cs.Factory.Core().V1().Services().Informer().GetIndexer().ByIndex(ServiceIpIndex, ip)
	if err != nil {
		return "", "", "", err
	}

	if len(objs) == 0 {
		return "", "", "", fmt.Errorf("service information is empty")
	}

	service := objs[0].(*corev1.Service)

	return service.GetNamespace(), service.Name, service.Kind, nil
}

func (cs *ClusterServer) IsServiceIp(ip string) bool {
	_, err := cs.Factory.Core().V1().Services().Informer().GetIndexer().ByIndex(ServiceIpIndex, ip)
	if err != nil {
		return false
	}
	return true
}

func (cs *ClusterServer) FilterMicroSegLog(log *model.TensorMicrosegEvent) bool {
	nowtime := time.Now().Unix()
	key := fmt.Sprintf("%s:%d", log.SrcIP, log.SrcPort)
	value, ok := cs.MicroSegLogCache[key]
	if ok {
		if (nowtime - value) < 20 {
			if log.Action != 0 {
				delete(cs.MicroSegLogCache, key)
			}
			return true
		}
	}

	cs.MicroSegLogCache[key] = nowtime

	/*clear invalid data*/
	if len(cs.MicroSegLogCache) > 500 {
		for k, v := range cs.MicroSegLogCache {
			if (nowtime - v) > 30 {
				delete(cs.MicroSegLogCache, k)
			}
		}
	}

	return false
}

func (cs *ClusterServer) FillResToMicroSegLogDetails(log *model.TensorMicrosegEvent) bool {
	src, err := cs.GetPodByIp(log.SrcIP)
	if err == nil {
		log.SrcNamespace = src.Namespace
		log.SrcResName = src.Resource
		log.SrcResKind = src.KindName
	} else {
		srcSvc := cs.IsServiceIp(log.SrcIP)
		if srcSvc {
			ns, res, kind, err := cs.GetServiceResByIp(log.SrcIP)
			if err == nil {
				log.SrcNamespace = ns
				log.SrcResName = res
				log.SrcResKind = kind
			}
		}
	}

	dst, err := cs.GetPodByIp(log.DstIP)
	if err == nil {
		log.DstNamespace = dst.Namespace
		log.DstResName = dst.Resource
		log.DstResKind = dst.KindName
	} else {
		dstSvc := cs.IsServiceIp(log.DstIP)
		if dstSvc {
			ns, res, kind, err := cs.GetServiceResByIp(log.DstIP)
			if err == nil {
				log.DstNamespace = ns
				log.DstResName = res
				log.DstResKind = kind
			}
		}
	}

	if log.Action != 0 {
		id, err := strconv.Atoi(log.PolicyName)
		if err != nil {
			logging.Get().Warn().Msgf("string(%+v) convert int failed, %+v", log.PolicyName, err)
		} else {
			srcObj, dstObj, err := cs.logFilter.GetPolicy(id)
			if err != nil {
				logging.Get().Warn().Msgf("get policy name failed, %+v", err)
			} else {
				log.SrcPodName = srcObj
				log.DstPodName = dstObj
			}
		}
	} else {
		if len(log.SrcResName) != 0 {
			log.SrcPodName = cs.logFilter.QueryResourceType(Resource, log.SrcResName)
		} else {
			log.SrcPodName = cs.logFilter.QueryResourceType(IPBlock, log.SrcIP)
		}

		if len(log.DstResName) != 0 {
			log.DstPodName = cs.logFilter.QueryResourceType(Resource, log.DstResName)
		} else {
			log.DstPodName = cs.logFilter.QueryResourceType(IPBlock, log.DstIP)
		}
	}

	if log.SrcPodName == "" && log.DstPodName == "" {
		logging.Get().Warn().Msgf("")
		return false
	}

	log.CreatedAt = time.Now().UnixMilli()

	return true
}

func (cs *ClusterServer) FillResToMicroSegLog(microLog *model.TensorMicrosegEvent) bool {
	src, err := cs.GetPodByIp(microLog.SrcIP)
	if err == nil {
		microLog.SrcNamespace = src.Namespace
		microLog.SrcResName = src.Resource
		microLog.SrcResKind = src.KindName
		microLog.SrcPodName = src.PodName
	} else {
		srcSvc := cs.IsServiceIp(microLog.SrcIP)
		if srcSvc {
			ns, res, kind, err := cs.GetServiceResByIp(microLog.SrcIP)
			if err == nil {
				microLog.SrcNamespace = ns
				microLog.SrcResName = res
				microLog.SrcResKind = kind
			}
		}
	}

	dst, err := cs.GetPodByIp(microLog.DstIP)
	if err == nil {
		microLog.DstNamespace = dst.Namespace
		microLog.DstResName = dst.Resource
		microLog.DstResKind = dst.KindName
		microLog.DstPodName = dst.PodName
	} else {
		dstSvc := cs.IsServiceIp(microLog.DstIP)
		if dstSvc {
			ns, res, kind, err := cs.GetServiceResByIp(microLog.DstIP)
			if err == nil {
				microLog.DstNamespace = ns
				microLog.DstResName = res
				microLog.DstResKind = kind
			}
		}
	}

	if microLog.SrcResName == "" && microLog.DstResName == "" {
		logging.Get().Warn().Msgf("")
		return false
	}

	switch microLog.Action {
	case 0:
		microLog.ActionStr = "Deny"
	case 1:
		microLog.ActionStr = "Allow"
	case 2:
		microLog.ActionStr = "Alert"
	}

	switch microLog.Proto {
	case 1:
		microLog.ProtoStr = "ICMP"
	case 6:
		microLog.ProtoStr = "TCP"
	case 17:
		microLog.ProtoStr = "UDP"
	}

	microLog.CreatedAt = time.Now().UnixMilli()
	microLog.ClusterKey = cs.ClusterID

	return true
}
