package microseg

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"strings"
	"time"

	"github.com/segmentio/kafka-go"
	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/model"
	"gitlab.com/security-rd/go-pkg/mq"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/generated/clientset/versioned"
	"scm.tensorsecurity.cn/tensorsecurity-rd/api/pkg/generated/informers/externalversions"

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
}

func NewRuleGroupController(clientset *versioned.Clientset, crdFactory externalversions.SharedInformerFactory, cli PolicyClient, nodeName string, mqWriter mq.Writer) *RuleGroupController {
	ruleInformer := crdFactory.Microsegmentation().V1alpha1().NetworkPolicyRuleGroups().Informer()
	controller := &RuleGroupController{
		ruleInformer:    ruleInformer,
		ruleLister:      crdFactory.Microsegmentation().V1alpha1().NetworkPolicyRuleGroups().Lister(),
		ruleGroupSynced: ruleInformer.HasSynced,
		queue:           workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "rulegroup-queue"),
		polCli:          cli,
		nodeName:        nodeName,
		mqSender:        mqWriter,
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

		if r.FromIPBlock != nil {
			newRule.FromAddress = append(newRule.FromAddress, Address{IP: r.FromIPBlock.CIDR})
		}

		for _, a := range r.ToAddresses {
			newRule.ToAddresses = append(newRule.ToAddresses, addressFromRule(&a))
		}
		if r.ToIPBlock != nil {
			newRule.ToAddresses = append(newRule.ToAddresses, Address{IP: r.ToIPBlock.CIDR})
		}
		rules = append(rules, newRule)
	}
	message.Rules = rules
	return message
}

func (rg *RuleGroupController) handlePolicyStatus(err error, ruleGroup *crdv1alpha1.NetworkPolicyRuleGroup) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	var intStatus int
	var detail string
	if err != nil {
		intStatus = 1
		detail = err.Error()
	}
	status := &model.PolicyStatus{
		Policy: ruleGroup.Spec.Policy,
		Status: intStatus,
		Detail: detail,
	}
	data, err := json.Marshal(status)
	if err != nil {
		logging.Get().Err(err).Msg("marshal policy status")
		return
	}

	err = rg.mqSender.Write(ctx, "ivan_microseg_status", kafka.Message{
		Value: data,
	})
	if err != nil {
		logging.Get().Err(err).Msg("send policy status to mq")
	}
}

func (rg *RuleGroupController) syncPolicy(name string) error {
	rule, err := rg.ruleLister.Get(name)
	if err != nil {
		if errors.IsNotFound(err) {
			log.Info().Msgf("deleting policy: %s", name)
			policyName := strings.TrimSuffix(name, "-"+rg.nodeName)
			err = rg.polCli.DeletePolicy(&PolicyRule{
				MessageType: 4,
				PolicyName:  policyName,
			})
			return err
		}
		log.Err(err).Msgf("get rulegroup %s err ", name)
		return err
	}

	data, err := json.Marshal(rule)
	if err != nil {
		log.Err(err).Msgf("marshal rulegroup %s err ", name)
		return err
	}
	log.Info().Msgf("policy rule: %s", string(data))

	msg := buildPolicyRuleMessage(3, rule)
	err = rg.polCli.AddPolicy(msg)
	rg.handlePolicyStatus(err, rule)
	if err != nil {
		logging.Get().Err(err).Msgf("send rule message err")
		return err
	}

	// msgData, err := json.Marshal(msg)
	// if err != nil {
	// 	log.Err(err).Msgf("marshal rulegroup %s err ", name)
	// 	return err
	// }
	// log.Info().Msgf("policy rule msg to dp: %s", string(msgData))

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
	wait.Until(rg.worker, time.Second, stopChan)
}

func (rg *RuleGroupController) worker() {
	log.Info().Msg("start worker")
	for rg.processNextItem() {
	}
}

func (rg *RuleGroupController) ReSyncAllPolicy() error {
	logging.Get().Info().Msg("resync all policies")
	ruleList, err := rg.ruleLister.List(labels.Everything())
	if err != nil {
		return err
	}
	for _, r := range ruleList {
		rg.syncPolicy(r.Name)
		if err != nil {
			return err
		}
	}
	return nil
}
