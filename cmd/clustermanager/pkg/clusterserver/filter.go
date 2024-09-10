package clusterserver

import (
	"bytes"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/clustermanager/pkg/constants"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gitlab.com/security-rd/go-pkg/databases"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/model"
	"gorm.io/gorm"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	discoveryv1beta1 "k8s.io/api/discovery/v1beta1"
	"k8s.io/apimachinery/pkg/labels"
)

type MicroSegLogFilter struct {
	IsFilterService bool
	db              *databases.RDBInstance
}

func IpInRange(ipStr string, ranges []string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	bytesCompare := func(a, b net.IP) int {
		return bytes.Compare(a.To4(), b.To4())
	}

	for _, r := range ranges {
		if strings.Contains(r, "-") { // 处理 IP 范围
			bounds := strings.Split(r, "-")

			startIP := net.ParseIP(bounds[0])
			endParts := strings.Split(bounds[0], ".")

			endIP := net.ParseIP(strings.Join(endParts[:len(endParts)-1], ".") + "." + bounds[1])
			if startIP == nil || endIP == nil {
				continue
			}
			if bytesCompare(ip, startIP) >= 0 && bytesCompare(ip, endIP) <= 0 {
				return true
			}
		} else if _, netCIDR, err := net.ParseCIDR(r); err == nil { // 处理 CIDR 表达式
			if netCIDR.Contains(ip) {
				return true
			}
		} else { // 处理单个 IP 地址
			compareIP := net.ParseIP(r)
			if compareIP != nil && ip.Equal(compareIP) {
				return true
			}
		}
	}

	return false
}

func (p *MicroSegLogFilter) QueryResourceType(dataType MicroType, data string) string {
	switch dataType {
	case Resource:
		if p.db == nil {
			return data
		}
		var res []model.TensorMicrosegResource
		err := p.db.Get().Model(&model.TensorMicrosegResource{}).Where("name=?", data).Find(&res).Error
		if err != nil && err != gorm.ErrRecordNotFound {
			logging.Get().Error().Msgf("microseglog scan resource information failed, %+v", err)
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
		if p.db == nil {
			return "Unknown"
		}
		var ips []model.IPGroup
		err := p.db.Get().Model(&model.IPGroup{}).Scan(&ips).Error
		if err != nil {
			logging.Get().Error().Msgf("microseglog scan ip group information failed, %+v", err)
			return "Unknown"
		}

		for i := 0; i < len(ips); i++ {
			ipStr := strings.Split(ips[i].IpSet, ",")
			ok := IpInRange(data, ipStr)
			if ok {
				return ips[i].Name
			}
		}
	}
	return "Unknown"
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
		ig := &model.IPGroup{}
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
	objs, err := cs.Factory.Core().V1().Pods().Informer().GetIndexer().ByIndex(constants.PodIpIndex, ip)
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
	objs, err := cs.Factory.Core().V1().Services().Informer().GetIndexer().ByIndex(constants.ServiceIpIndex, ip)
	if err != nil {
		return "", "", "", err
	}

	if len(objs) == 0 {
		return "", "", "", fmt.Errorf("service information is empty")
	}

	service := objs[0].(*corev1.Service)
	logging.Get().Info().Msgf("service traffic: %s, name: %s", ip, service.Name)

	var workLoadName, kind string
	if cs.EndpointsV1 {
		workLoadName, kind, err = cs.getNameAndKindV1(service)
		if err != nil {
			return "nil", "", "", err
		}
	} else {
		workLoadName, kind, err = cs.getNameAndKindV1Beta1(service)
		if err != nil {
			return "nil", "", "", err
		}
	}
	// epslices, err := cs.Factory.Discovery().V1().EndpointSlices().Lister().List(labels.SelectorFromValidatedSet(map[string]string{
	// 	"kubernetes.io/service-name":             service.Name,
	// 	"endpointslice.kubernetes.io/managed-by": "endpointslice-controller.k8s.io",
	// }))
	// if err != nil {
	// 	logging.Get().Err(err).Msg("get ep owner service")
	// 	return "", "", "", err
	// }
	// cs.Factory.Discovery().V1beta1().EndpointSlices().Lister()

	// logging.Get().Info().Msgf("epslice: %+v", epslices)

	// var epslice *discoveryv1.EndpointSlice
	// for _, slice := range epslices {
	// 	if slice.Namespace == service.Namespace {
	// 		epslice = slice
	// 	}
	// }
	// var workLoadName, kind string
	// logging.Get().Info().Msgf("epslices len: %+v", len(epslices))
	// if epslice != nil {
	// 	logging.Get().Info().Msgf("endpoints: %+v", epslice.Endpoints)
	// 	if len(epslice.Endpoints) > 0 {
	// 		ep := epslice.Endpoints[0]
	// 		logging.Get().Info().Msgf("endpoint: %+v", ep)
	// 		if ep.TargetRef.Kind == "Pod" {
	// 			pod, exist, err := cs.Factory.Core().V1().Pods().Informer().GetIndexer().GetByKey(fmt.Sprintf("%s/%s", ep.TargetRef.Namespace, ep.TargetRef.Name))
	// 			if err != nil {
	// 				return "", "", "", err
	// 			}
	// 			if !exist {
	// 				return "", "", "", fmt.Errorf("not found pod for service")
	// 			}
	// 			workLoadName, kind = util.GetOwnerOfPod(pod.(*corev1.Pod))
	// 		} else {
	// 			return "", "", "", fmt.Errorf("no pod for service")
	// 		}
	// 	}
	// }

	return service.GetNamespace(), workLoadName, kind, nil
}

func (cs *ClusterServer) getNameAndKindV1(service *corev1.Service) (string, string, error) {
	epslices, err := cs.Factory.Discovery().V1().EndpointSlices().Lister().List(labels.SelectorFromValidatedSet(map[string]string{
		"kubernetes.io/service-name":             service.Name,
		"endpointslice.kubernetes.io/managed-by": "endpointslice-controller.k8s.io",
	}))
	if err != nil {
		logging.Get().Err(err).Msg("get ep owner service")
		return "", "", err
	}
	cs.Factory.Discovery().V1beta1().EndpointSlices().Lister()

	logging.Get().Info().Msgf("epslice: %+v", epslices)

	var epslice *discoveryv1.EndpointSlice
	for _, slice := range epslices {
		if slice.Namespace == service.Namespace {
			epslice = slice
		}
	}
	var workLoadName, kind string
	logging.Get().Info().Msgf("epslices len: %+v", len(epslices))
	if epslice != nil {
		logging.Get().Info().Msgf("endpoints: %+v", epslice.Endpoints)
		if len(epslice.Endpoints) > 0 {
			ep := epslice.Endpoints[0]
			logging.Get().Info().Msgf("endpoint: %+v", ep)
			if ep.TargetRef.Kind == "Pod" {
				pod, exist, err := cs.Factory.Core().V1().Pods().Informer().GetIndexer().GetByKey(fmt.Sprintf("%s/%s", ep.TargetRef.Namespace, ep.TargetRef.Name))
				if err != nil {
					return "", "", err
				}
				if !exist {
					return "", "", fmt.Errorf("not found pod for service")
				}
				workLoadName, kind = util.GetOwnerOfPod(pod.(*corev1.Pod))
			} else {
				return "", "", fmt.Errorf("no pod for service")
			}
		}
	}
	return workLoadName, kind, err
}

func (cs *ClusterServer) getNameAndKindV1Beta1(service *corev1.Service) (string, string, error) {
	epslices, err := cs.Factory.Discovery().V1beta1().EndpointSlices().Lister().List(labels.SelectorFromValidatedSet(map[string]string{
		"kubernetes.io/service-name":             service.Name,
		"endpointslice.kubernetes.io/managed-by": "endpointslice-controller.k8s.io",
	}))
	if err != nil {
		logging.Get().Err(err).Msg("get ep owner service")
		return "", "", err
	}
	cs.Factory.Discovery().V1beta1().EndpointSlices().Lister()

	logging.Get().Info().Msgf("epslice: %+v", epslices)

	var epslice *discoveryv1beta1.EndpointSlice
	for _, slice := range epslices {
		if slice.Namespace == service.Namespace {
			epslice = slice
		}
	}
	var workLoadName, kind string
	logging.Get().Info().Msgf("epslices len: %+v", len(epslices))
	if epslice != nil {
		logging.Get().Info().Msgf("endpoints: %+v", epslice.Endpoints)
		if len(epslice.Endpoints) > 0 {
			ep := epslice.Endpoints[0]
			logging.Get().Info().Msgf("endpoint: %+v", ep)
			if ep.TargetRef.Kind == "Pod" {
				pod, exist, err := cs.Factory.Core().V1().Pods().Informer().GetIndexer().GetByKey(fmt.Sprintf("%s/%s", ep.TargetRef.Namespace, ep.TargetRef.Name))
				if err != nil {
					return "", "", err
				}
				if !exist {
					return "", "", fmt.Errorf("not found pod for service")
				}
				workLoadName, kind = util.GetOwnerOfPod(pod.(*corev1.Pod))
			} else {
				return "", "", fmt.Errorf("no pod for service")
			}
		}
	}
	return workLoadName, kind, err
}

func (cs *ClusterServer) IsServiceIp(ip string) bool {
	_, err := cs.Factory.Core().V1().Services().Informer().GetIndexer().ByIndex(constants.ServiceIpIndex, ip)
	return err == nil
}

func (cs *ClusterServer) FilterMicroSegLog(log *model.TensorMicrosegEvent) bool {
	key := fmt.Sprintf("%+v:%+v:%+v:%+v:%+v", log.Proto, log.SrcIP, log.SrcPort, log.DstIP, log.DstPort)
	_, ok := cs.MicroSegLogCache[key]
	if ok {
		delete(cs.MicroSegLogCache, key)
		return true
	}
	//now time
	nowTime := time.Now().Unix()
	//save
	cs.MicroSegLogCache[key] = nowTime

	/*clear invalid data*/
	if len(cs.MicroSegLogCache) < 2000 {
		return false
	}

	for k, v := range cs.MicroSegLogCache {
		if (nowTime - v) < 10 {
			continue
		}
		delete(cs.MicroSegLogCache, k)
	}

	return false
}

func (cs *ClusterServer) GetResource(microLog *model.TensorMicrosegEvent) {
	src, err := cs.GetPodByIp(microLog.SrcIP)
	if err == nil {
		microLog.SrcNamespace = src.Namespace
		microLog.SrcResName = src.Resource
		microLog.SrcResKind = src.KindName
		microLog.SrcPodName = src.PodName
	} else {
		srcSvc := cs.IsServiceIp(microLog.SrcIP)
		if srcSvc {
			// return false
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
			// return false
			ns, res, kind, err := cs.GetServiceResByIp(microLog.DstIP)
			if err == nil {
				microLog.DstNamespace = ns
				microLog.DstResName = res
				microLog.DstResKind = kind
			}
		}
	}
}

func (cs *ClusterServer) FillResByPolicyId(id int, log *model.TensorMicrosegEvent) {
	cs.GetResource(log)
	if len(log.SrcResName) != 0 && len(log.DstResName) != 0 {
		return
	}

	srcObj, dstObj, err := cs.logFilter.GetPolicy(id)
	if err != nil {
		logging.Get().Warn().Msgf("get policy name failed, %+v", err)
		return
	}

	if len(log.SrcResName) == 0 {
		log.SrcResName = srcObj
	}

	if len(log.DstResName) == 0 {
		log.DstResName = dstObj
	}
}

func (cs *ClusterServer) FillResByPolicyName(microLog *model.TensorMicrosegEvent) {
	cs.GetResource(microLog)

	if len(microLog.SrcResName) == 0 {
		microLog.SrcResKind = "Internal"
		microLog.SrcResName = cs.logFilter.QueryResourceType(IPBlock, microLog.SrcIP)
		if microLog.SrcResName == "Unknown" {
			microLog.SrcResKind = "Unknown"
		}
	}

	if len(microLog.DstResName) == 0 {
		microLog.DstResKind = "Internal"
		microLog.DstResName = cs.logFilter.QueryResourceType(IPBlock, microLog.DstIP)
		if microLog.DstResName == "Unknown" {
			microLog.DstResKind = "Unknown"
		}
	}
}

func (cs *ClusterServer) FillResToMicroSegLog(microLog *model.TensorMicrosegEvent) bool {
	id, err := strconv.Atoi(microLog.PolicyName)
	if err != nil {
		cs.FillResByPolicyName(microLog)
	} else {
		cs.FillResByPolicyId(id, microLog)
	}

	if microLog.SrcResName == "" && microLog.DstResName == "" {
		logging.Get().Warn().Msgf("microseglog get resource kind failed")
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
