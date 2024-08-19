package microseg

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash"
	"hash/fnv"
	"slices"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/google/uuid"
	"github.com/segmentio/kafka-go"
	heavyagent "gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/heavy-agent"
	"gitlab.com/piccolo_su/vegeta/cmd/daemon/pkg/microseg/types/microseg"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/model"
	"gitlab.com/security-rd/go-pkg/mq"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/generated/clientset/versioned"
	"scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/generated/informers/externalversions"

	apiequality "k8s.io/apimachinery/pkg/api/equality"
	hashutil "k8s.io/kubernetes/pkg/util/hash"
	crdv1alpha1 "scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/apis/microsegmentation.security.io/v1alpha1"
	"scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/generated/listers/microsegmentation.security.io/v1alpha1"
)

const maxRetries = 15

var log = logging.Get().With().Str("module", "microseg").Logger()

type RuleGroupController struct {
	ruleInformer    cache.SharedIndexInformer
	ruleLister      v1alpha1.NetworkPolicyRuleGroupLister
	ruleGroupSynced cache.InformerSynced
	queue           workqueue.RateLimitingInterface
	polCli          PolicyClient
	nodeName        string
	mqSender        mq.Writer
	agentCli        *heavyagent.Client
	ruleMap         map[string]sets.String
}

func NewRuleGroupController(clientset *versioned.Clientset, crdFactory externalversions.SharedInformerFactory, cli PolicyClient, nodeName string, mqWriter mq.Writer, agentCli *heavyagent.Client) *RuleGroupController {
	ruleInformer := crdFactory.Microsegmentation().V1alpha1().NetworkPolicyRuleGroups().Informer()
	controller := &RuleGroupController{
		ruleInformer:    ruleInformer,
		ruleLister:      crdFactory.Microsegmentation().V1alpha1().NetworkPolicyRuleGroups().Lister(),
		ruleGroupSynced: ruleInformer.HasSynced,
		queue:           workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "rulegroup-queue"),
		polCli:          cli,
		nodeName:        nodeName,
		mqSender:        mqWriter,
		agentCli:        agentCli,
		ruleMap:         make(map[string]sets.String),
	}
	ruleInformer.AddEventHandlerWithResyncPeriod(cache.ResourceEventHandlerFuncs{
		AddFunc:    controller.addRuleGroup,
		UpdateFunc: controller.updateRuleGroup,
		DeleteFunc: controller.deleteRuleGroup,
	}, time.Hour*8)

	cli.AddReConnectionCallback(controller.ReSyncAllPolicy)
	return controller
}

var KeyFunc = cache.DeletionHandlingMetaNamespaceKeyFunc

func (rg *RuleGroupController) addRuleGroup(object interface{}) {
	rule := object.(*crdv1alpha1.NetworkPolicyRuleGroup)
	key, err := KeyFunc(rule)
	if err != nil {
		return
	}
	rg.queue.Add(key)
}

func (rg *RuleGroupController) updateRuleGroup(oldObj, newObject interface{}) {
	rule := newObject.(*crdv1alpha1.NetworkPolicyRuleGroup)
	key, err := KeyFunc(rule)
	if err != nil {
		return
	}
	rg.queue.Add(key)
}

func (rg *RuleGroupController) deleteRuleGroup(object interface{}) {
	rule := object.(*crdv1alpha1.NetworkPolicyRuleGroup)
	key, err := KeyFunc(rule)
	if err != nil {
		return
	}
	rg.queue.Add(key)
}

func (rg *RuleGroupController) handleErr(err error, key interface{}) {
	if err == nil {
		rg.queue.Forget(key)
		return
	}
	if rg.queue.NumRequeues(key) < maxRetries {
		log.Err(err).Msgf("Error syncing policy rule, retrying %s", key)
		rg.queue.AddRateLimited(key)
		return
	}

	log.Warn().Msgf("Dropping policy rule %q out of the queue: %v", key, err)
	rg.queue.Forget(key)
	// utilruntime.HandleError(err)
}

func podID(e *crdv1alpha1.EntityReference) uint64 {
	str := fmt.Sprintf("%s/%s", e.Namespace, e.Name)
	logging.Get().Info().Msgf("sync pod :%s", str)
	h := fnv.New64a()
	h.Write([]byte(str))
	return h.Sum64()
}

func addressFromRule(a *crdv1alpha1.Address) Address {
	addr := Address{IP: a.IP}
	if a.PodReference != nil {
		addr.PodID = podID(a.PodReference)
	}
	return addr
}

// func isDenyAllPolicy(ruleGroup *crdv1alpha1.NetworkPolicyRuleGroup) bool {
// 	return strings.Contains(ruleGroup.Name, "-deny-all-")
// }

func buildPolicyRuleMessage(msgType int, ruleGroup *crdv1alpha1.NetworkPolicyRuleGroup) *PolicyRule {
	message := &PolicyRule{
		MessageType: msgType,
		PolicyName:  ruleGroup.Spec.Policy,
	}
	var rules []NodeRule
	for _, r := range ruleGroup.Spec.Rules {
		newRule := NodeRule{
			Action:    r.Action,
			Direction: r.Direction,
			Priority:  r.Priority,
			Protocol:  r.Protocol,
			Ports:     r.Ports,
		}
		if r.Http != nil {
			newRule.Http = []*crdv1alpha1.Http{r.Http}
		}
		for _, a := range r.FromAddress {
			newRule.FromAddress = append(newRule.FromAddress, addressFromRule(&a))
		}
		for _, ipBlock := range r.FromIPBlock {
			newRule.FromAddress = append(newRule.FromAddress, Address{IP: ipBlock.CIDR})
		}

		for _, a := range r.ToAddresses {
			newRule.ToAddresses = append(newRule.ToAddresses, addressFromRule(&a))
		}
		for _, ipBlock := range r.ToIPBlock {
			newRule.ToAddresses = append(newRule.ToAddresses, Address{IP: ipBlock.CIDR})
		}

		slices.SortStableFunc(newRule.FromAddress, func(a, b Address) int {
			if a.IP != b.IP {
				return strings.Compare(a.IP, b.IP)
			}
			if a.PodID < b.PodID {
				return -1
			}
			if a.PodID > b.PodID {
				return 1
			}
			return 0
		})

		slices.SortStableFunc(newRule.ToAddresses, func(a, b Address) int {
			if a.IP != b.IP {
				return strings.Compare(a.IP, b.IP)
			}
			if a.PodID < b.PodID {
				return -1
			}
			if a.PodID > b.PodID {
				return 1
			}
			return 0
		})

		rules = append(rules, newRule)
	}
	message.Rules = rules
	return message
}

// DeepHashObject writes specified object to hash using the spew library
// which follows pointers and prints actual values of the nested objects
// ensuring the hash does not change when a pointer changes.
func DeepHashObject(hasher hash.Hash, objectToWrite interface{}) {
	hasher.Reset()
	// fmt.Fprintf(hasher, "%v", dump.ForHash(objectToWrite))
	printer := spew.ConfigState{
		Indent:         " ",
		SortKeys:       true,
		DisableMethods: true,
		SpewKeys:       true,
	}
	printer.Fprintf(hasher, "%#v", objectToWrite)
}

func ComputeHash(template *crdv1alpha1.NodeRule, collisionCount *int32) string {
	nodeRules := fnv.New32a()
	// DeepHashObject(podTemplateSpecHasher, *template)
	hashutil.DeepHashObject(nodeRules, *template)

	// Add collisionCount in the hash if it exists.
	if collisionCount != nil {
		collisionCountBytes := make([]byte, 8)
		binary.LittleEndian.PutUint32(collisionCountBytes, uint32(*collisionCount))
		nodeRules.Write(collisionCountBytes)
	}

	return rand.SafeEncodeString(fmt.Sprint(nodeRules.Sum32()))
}

func buildPolicyRuleMessages1(msgType int, crdRules []crdv1alpha1.NodeRule) []PolicyRule {
	ruleMaps := make(map[string]*PolicyRule)
	var rules []PolicyRule
	for _, r := range crdRules {
		if _, exists := ruleMaps[r.Name]; !exists {
			// The rule does not exist in the map, so you can add it or perform other actions
			ruleMaps[r.Name] = &PolicyRule{
				MessageType: msgType,
				PolicyName:  r.Name,
			}
		}
		// var rules []NodeRule
		// message := PolicyRule{
		// 	MessageType: msgType,
		// 	PolicyName:  r.Name + "-" + ComputeHash(&r, nil),
		// }

		newRule := NodeRule{
			Action:    r.Action,
			Direction: r.Direction,
			Priority:  r.Priority,
			Protocol:  r.Protocol,
			Ports:     r.Ports,
		}

		if r.Http != nil {
			newRule.Http = []*crdv1alpha1.Http{r.Http}
		}
		for _, a := range r.FromAddress {
			newRule.FromAddress = append(newRule.FromAddress, addressFromRule(&a))
		}
		for _, ipBlock := range r.FromIPBlock {
			newRule.FromAddress = append(newRule.FromAddress, Address{IP: ipBlock.CIDR})
		}

		for _, a := range r.ToAddresses {
			newRule.ToAddresses = append(newRule.ToAddresses, addressFromRule(&a))
		}
		for _, ipBlock := range r.ToIPBlock {
			newRule.ToAddresses = append(newRule.ToAddresses, Address{IP: ipBlock.CIDR})
		}

		slices.SortStableFunc(newRule.FromAddress, func(a, b Address) int {
			if a.IP != b.IP {
				return strings.Compare(a.IP, b.IP)
			}
			if a.PodID < b.PodID {
				return -1
			}
			if a.PodID > b.PodID {
				return 1
			}
			return 0
		})

		slices.SortStableFunc(newRule.ToAddresses, func(a, b Address) int {
			if a.IP != b.IP {
				return strings.Compare(a.IP, b.IP)
			}
			if a.PodID < b.PodID {
				return -1
			}
			if a.PodID > b.PodID {
				return 1
			}
			return 0
		})

		// rules = append(rules, newRule)
		ruleMaps[r.Name].Rules = append(ruleMaps[r.Name].Rules, newRule)
		// rules = append(rules, message)
	}
	for _, r := range ruleMaps {
		rules = append(rules, *r)
	}
	return rules
}

func buildPolicyRuleMessages(msgType int, ruleGroup *crdv1alpha1.NetworkPolicyRuleGroup) []PolicyRule {
	var rules []PolicyRule
	for _, r := range ruleGroup.Spec.Rules {
		// var rules []NodeRule
		message := PolicyRule{
			MessageType: msgType,
			PolicyName:  r.Name,
		}

		newRule := NodeRule{
			Action:    r.Action,
			Direction: r.Direction,
			Priority:  r.Priority,
			Protocol:  r.Protocol,
			Ports:     r.Ports,
		}
		if r.Http != nil {
			newRule.Http = []*crdv1alpha1.Http{r.Http}
		}
		for _, a := range r.FromAddress {
			newRule.FromAddress = append(newRule.FromAddress, addressFromRule(&a))
		}
		for _, ipBlock := range r.FromIPBlock {
			newRule.FromAddress = append(newRule.FromAddress, Address{IP: ipBlock.CIDR})
		}

		for _, a := range r.ToAddresses {
			newRule.ToAddresses = append(newRule.ToAddresses, addressFromRule(&a))
		}
		for _, ipBlock := range r.ToIPBlock {
			newRule.ToAddresses = append(newRule.ToAddresses, Address{IP: ipBlock.CIDR})
		}

		slices.SortStableFunc(newRule.FromAddress, func(a, b Address) int {
			if a.IP != b.IP {
				return strings.Compare(a.IP, b.IP)
			}
			if a.PodID < b.PodID {
				return -1
			}
			if a.PodID > b.PodID {
				return 1
			}
			return 0
		})

		slices.SortStableFunc(newRule.ToAddresses, func(a, b Address) int {
			if a.IP != b.IP {
				return strings.Compare(a.IP, b.IP)
			}
			if a.PodID < b.PodID {
				return -1
			}
			if a.PodID > b.PodID {
				return 1
			}
			return 0
		})

		// rules = append(rules, newRule)
		message.Rules = append(message.Rules, newRule)
		rules = append(rules, message)
	}
	return rules
}

func (rg *RuleGroupController) handlePolicyStatus(err error, ruleName string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	var intStatus int
	var detail string
	if err != nil {
		intStatus = int(model.PrepareFailed)
		detail = err.Error()
	}
	status := &model.PolicyStatus{
		Policy: ruleName,
		Status: intStatus,
		Detail: detail,
	}
	data, err := json.Marshal(status)
	if err != nil {
		logging.Get().Err(err).Msg("marshal policy status")
		return
	}

	logging.Get().Info().Msgf("update policy status %s", data)
	err = rg.mqSender.Write(ctx, "ivan_microseg_status", kafka.Message{
		Value: data,
	})
	if err != nil {
		logging.Get().Err(err).Msg("send policy status to mq")
	}
}

func (rg *RuleGroupController) syncPolicy(name string) error {
	ruleGroup, err := rg.ruleLister.Get(name)
	if err != nil {
		if errors.IsNotFound(err) {
			log.Info().Msgf("deleting policy: %s", name)
			// policyName := strings.TrimSuffix(name, "-"+rg.nodeName)
			if ruleSets, ok := rg.ruleMap[name]; ok {
				for name := range ruleSets {
					err = rg.polCli.DeletePolicy(&PolicyRule{
						MessageType: 4,
						PolicyName:  name,
					})
					logging.Get().Error().Msgf("delete rule %s error: %v", name, err)
				}
			}
			return nil
		}
		log.Err(err).Msgf("get rulegroup %s err ", name)
		return err
	}

	data, err := json.Marshal(ruleGroup)
	if err != nil {
		log.Err(err).Msgf("marshal rulegroup %s err ", name)
		return err
	}
	log.Info().Msgf("policy rule: %s", string(data))

	// msg := buildPolicyRuleMessage(3, rule)
	ruleNameSets := sets.NewString()
	for _, r := range ruleGroup.Spec.Rules {
		ruleNameSets.Insert(r.Name)
	}

	deletedRules := rg.ruleMap[ruleGroup.Name].Difference(ruleNameSets).List()
	log.Info().Msgf("deleted rules: %+v", deletedRules)
	for _, ruleName := range deletedRules {
		err = rg.polCli.DeletePolicy(&PolicyRule{
			MessageType: 4,
			PolicyName:  ruleName,
		})
		logging.Get().Error().Msgf("delete rule %s error: %v", ruleName, err)
	}

	// addedRules := ruleNameSets.Intersection(rg.ruleMap[rule.Spec.Policy])
	msgs := buildPolicyRuleMessages1(3, ruleGroup.Spec.Rules)
	for _, msg := range msgs {
		err = rg.polCli.AddPolicy(&msg)
		rg.handlePolicyStatus(err, msg.PolicyName)
		if err != nil {
			logging.Get().Err(err).Msgf("send rule message err")
			return err
		}
	}

	rg.ruleMap[name] = ruleNameSets
	return nil
}

func (rg *RuleGroupController) processNextItem() bool {
	key, quit := rg.queue.Get()
	if quit {
		return false
	}
	defer rg.queue.Done(key)

	policyName := key.(string)
	err := rg.syncPolicy(policyName)
	rg.handleErr(err, key)

	return true
}

func (rg *RuleGroupController) Run(stopChan chan struct{}) {
	log.Info().Msg("run Network Policy Controller")
	if !cache.WaitForNamedCacheSync("network_policy", stopChan, rg.ruleGroupSynced) {
		return
	}
	rgList, err := rg.ruleLister.List(labels.Everything())
	if err != nil {
		return
	}
	for _, ruleGroup := range rgList {
		for _, rule := range ruleGroup.Spec.Rules {
			if _, ok := rg.ruleMap[ruleGroup.Name]; !ok {
				rg.ruleMap[ruleGroup.Name] = sets.NewString()
			}
			rg.ruleMap[ruleGroup.Name].Insert(rule.Name)
		}
	}

	go func() {
		time.Sleep(time.Minute * 2)
		wait.PollImmediateInfinite(time.Minute*5, func() (done bool, err error) {
			err = rg.checkSync()
			if err != nil {
				logging.Get().Err(err).Msg("check syncing")
			}
			return false, nil
		})
	}()

	wait.Until(rg.worker, time.Second, stopChan)
}

func (rg *RuleGroupController) worker() {
	log.Info().Msg("start worker")
	for rg.processNextItem() {
	}
}

func (rg *RuleGroupController) ReSyncAllPolicy() error {
	log.Info().Msg("resync all policies")
	ruleList, err := rg.ruleLister.List(labels.Everything())
	if err != nil {
		return err
	}
	for _, r := range ruleList {
		err = rg.syncPolicy(r.Name)
		if err != nil {
			return err
		}
	}
	return nil
}

func (rg *RuleGroupController) checkSync() error {
	log.Info().Msg("check all policies")
	ruleList, err := rg.ruleLister.List(labels.Everything())
	if err != nil {
		return err
	}
	req := microseg.ConfigDumpReq{
		UUID:        uuid.NewString(),
		MessageType: 10,
	}
	data, err := json.Marshal(&req)
	if err != nil {
		return err
	}
	// err = rg.agentCli.Send(data)
	// if err != nil {
	// 	return err
	// }

	// var resp microseg.ConfigDumpResp
	// err = rg.agentCli.ReceiveMessage(&resp)
	// if err != nil {
	// 	return err
	// }

	var resp microseg.ConfigDumpResp
	err = rg.agentCli.SendAndReceiveMessage(data, &resp)
	if err != nil {
		return err
	}

	logging.Get().Info().Msgf("agent config inbound: %d, outbound %d", len(resp.Body.InboundRules), len(resp.Body.OutboundRules))

	// group by name
	ruleMap := make(map[string][]microseg.SingleRule, 3)
	for _, r := range resp.Body.InboundRules {
		protocol := r.Protocol
		if r.Protocol == "" {
			protocol = "ANY"
		}
		if _, ok := ruleMap[r.PolicyName]; ok {
			ruleMap[r.PolicyName] = append(ruleMap[r.PolicyName], microseg.SingleRule{
				PolicyName:  r.PolicyName,
				Priority:    r.Priority,
				Direction:   r.Direction,
				Action:      r.Action,
				Protocol:    protocol,
				FromAddress: r.FromAddress,
				ToAddress:   r.ToAddress,
			})
		} else {
			ruleMap[r.PolicyName] = []microseg.SingleRule{
				{
					PolicyName:  r.PolicyName,
					Priority:    r.Priority,
					Direction:   r.Direction,
					Action:      r.Action,
					Protocol:    protocol,
					FromAddress: r.FromAddress,
					ToAddress:   r.ToAddress,
				},
			}
		}
	}

	for _, r := range resp.Body.OutboundRules {
		protocol := r.Protocol
		if r.Protocol == "" {
			protocol = "ANY"
		}
		if _, ok := ruleMap[r.PolicyName]; ok {
			ruleMap[r.PolicyName] = append(ruleMap[r.PolicyName], microseg.SingleRule{
				PolicyName:  r.PolicyName,
				Priority:    r.Priority,
				Direction:   r.Direction,
				Action:      r.Action,
				Protocol:    protocol,
				FromAddress: r.FromAddress,
				ToAddress:   r.ToAddress,
			})
		} else {
			ruleMap[r.PolicyName] = []microseg.SingleRule{
				{
					PolicyName:  r.PolicyName,
					Priority:    r.Priority,
					Direction:   r.Direction,
					Action:      r.Action,
					Protocol:    protocol,
					FromAddress: r.FromAddress,
					ToAddress:   r.ToAddress,
				},
			}
		}
	}
	for name := range ruleMap {
		rules := ruleMap[name][:]
		slices.SortStableFunc(rules, ruleSorer)
		ruleMap[name] = rules
	}

	desiredRuleMap := splitPolicyRules(ruleList)

	for k, v := range desiredRuleMap {
		if agentRules, ok := ruleMap[k]; ok {
			if !apiequality.Semantic.DeepEqual(v, ruleMap[k]) {
				ruleData, _ := json.Marshal(v)
				agentRuleData, _ := json.Marshal(agentRules)
				logging.Get().Warn().Msgf("policy: %s on daemon is in conflict with heavy-agent in node %s, rules: %s , agent rules: %s", k, rg.nodeName, ruleData, agentRuleData)
				rg.handlePolicyStatus(fmt.Errorf("policy: %s on daemon is in conflict with heavy-agent in node %s", k, rg.nodeName), k)
			} else {
				rg.handlePolicyStatus(nil, k)
			}
		} else {
			logging.Get().Warn().Msgf("heavy-agent lost policy %s", k)
			rg.handlePolicyStatus(fmt.Errorf("heavy-agent in node %s lost policy %s", rg.nodeName, k), k)
		}
	}

	// for _, r := range ruleList {
	// 	rules := splitPolicyRules(r)
	// 	if agentRules, ok := ruleMap[r.Spec.Policy]; ok {
	// 		if !apiequality.Semantic.DeepEqual(rules, agentRules) {
	// 			ruleData, _ := json.Marshal(rules)
	// 			agentRuleData, _ := json.Marshal(agentRules)
	// 			logging.Get().Warn().Msgf("policy: %s on daemon is in conflict with heavy-agent in node %s, rules: %s , agent rules: %s", r.Spec.Policy, rg.nodeName, ruleData, agentRuleData)
	// 			rg.handlePolicyStatus(fmt.Errorf("policy: %s on daemon is in conflict with heavy-agent in node %s", r.Spec.Policy, rg.nodeName), r.Name)
	// 		} else {
	// 			rg.handlePolicyStatus(nil, r)
	// 		}
	// 	} else {
	// 		logging.Get().Warn().Msgf("heavy-agent lost policy %s", r.Spec.Policy)
	// 		rg.handlePolicyStatus(fmt.Errorf("heavy-agent in node %s lost policy %s", rg.nodeName, r.Spec.Policy), r)
	// 	}
	// }
	return nil
}

// spit rules in policy into a set of single rules
func splitPolicyRules(ruleGroups []*crdv1alpha1.NetworkPolicyRuleGroup) map[string][]microseg.SingleRule {
	// var rules []microseg.SingleRule
	ruleMap := make(map[string][]microseg.SingleRule, 3)

	for _, ruleGroup := range ruleGroups {
		for _, r := range ruleGroup.Spec.Rules {
			for _, fromAddr := range r.FromAddress {
				for _, toAddr := range r.ToAddresses {
					if _, ok := ruleMap[r.Name]; !ok {
						ruleMap[r.Name] = []microseg.SingleRule{}
					}

					newRule := microseg.SingleRule{
						PolicyName: r.Name,
						Action:     r.Action,
						Direction:  r.Direction,
						Priority:   r.Priority,
						Protocol:   r.Protocol,
						// Ports:     r.Ports,
						FromAddress: fromAddr.IP,
						ToAddress:   toAddr.IP,
					}
					ruleMap[r.Name] = append(ruleMap[r.Name], newRule)
					// rules = append(rules, newRule)
				}
			}

			for _, fromAddr := range r.FromAddress {
				for _, toAddr := range r.ToIPBlock {
					toAddresses := strings.Split(toAddr.CIDR, ",")
					for _, toAddr1 := range toAddresses {
						if _, ok := ruleMap[r.Name]; !ok {
							ruleMap[r.Name] = []microseg.SingleRule{}
						}
						newRule := microseg.SingleRule{
							PolicyName: r.Name,
							Action:     r.Action,
							Direction:  r.Direction,
							Priority:   r.Priority,
							Protocol:   r.Protocol,
							// Ports:     r.Ports,
							FromAddress: fromAddr.IP,
							ToAddress:   toAddr1,
						}
						ruleMap[r.Name] = append(ruleMap[r.Name], newRule)
						// rules = append(rules, newRule)
					}
				}
			}

			for _, fromAddr := range r.FromIPBlock {
				fromAddresses := strings.Split(fromAddr.CIDR, ",")
				for _, fromAddr1 := range fromAddresses {
					for _, toAddr := range r.ToAddresses {
						if _, ok := ruleMap[r.Name]; !ok {
							ruleMap[r.Name] = []microseg.SingleRule{}
						}
						newRule := microseg.SingleRule{
							PolicyName:  r.Name,
							Action:      r.Action,
							Direction:   r.Direction,
							Priority:    r.Priority,
							Protocol:    r.Protocol,
							FromAddress: fromAddr1,
							ToAddress:   toAddr.IP,
						}
						ruleMap[r.Name] = append(ruleMap[r.Name], newRule)
						// rules = append(rules, newRule)
					}
				}
			}

			for _, fromAddr := range r.FromIPBlock {
				fromAddresses := strings.Split(fromAddr.CIDR, ",")
				for _, fromAddr1 := range fromAddresses {
					for _, toAddr := range r.ToIPBlock {
						toAddresses := strings.Split(toAddr.CIDR, ",")
						for _, toAddr1 := range toAddresses {
							if _, ok := ruleMap[r.Name]; !ok {
								ruleMap[r.Name] = []microseg.SingleRule{}
							}
							newRule := microseg.SingleRule{
								PolicyName:  r.Name,
								Action:      r.Action,
								Direction:   r.Direction,
								Priority:    r.Priority,
								Protocol:    r.Protocol,
								FromAddress: fromAddr1,
								ToAddress:   toAddr1,
							}
							ruleMap[r.Name] = append(ruleMap[r.Name], newRule)
							// rules = append(rules, newRule)
						}
					}
				}
			}
		}
	}

	for k, _ := range ruleMap {
		slices.SortStableFunc(ruleMap[k], ruleSorer)
	}
	// slices.SortStableFunc(rules, ruleSorer)
	// return rules
	return ruleMap
}

func ruleSorer(a, b microseg.SingleRule) int {
	if a.PolicyName != b.PolicyName {
		if a.PolicyName < b.PolicyName {
			return -1
		}
		return 1
	}
	if a.Priority != b.Priority {
		if a.Priority < b.Priority {
			return -1
		}
		return 1
	}
	if a.Direction != b.Direction {
		if a.Direction < b.Direction {
			return -1
		}
		return 1
	}
	if a.Action != b.Action {
		if a.Action < b.Action {
			return -1
		}
		return 1
	}
	if a.Protocol != b.Protocol {
		if a.Protocol < b.Protocol {
			return -1
		}
		return 1
	}
	if a.FromAddress != b.FromAddress {
		if a.FromAddress < b.FromAddress {
			return -1
		}
		return 1
	}
	if a.ToAddress < b.ToAddress {
		return -1
	}
	if a.ToAddress > b.ToAddress {
		return 1
	}
	return 0
}
