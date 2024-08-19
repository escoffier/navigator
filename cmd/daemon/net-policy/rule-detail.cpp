#include <algorithm>
#include <cstddef>
#include <memory>
#include <stdio.h>
#include <stdlib.h>
#include <string_view>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h> /* for NF_ACCEPT */
#include <errno.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <utility>
#include <string.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <dirent.h>
#include <fcntl.h>
#include <sched.h>
#include <map>
#include <iostream>
#include <iomanip>
#include <string>
#include <sys/time.h>
#include <gflags/gflags.h>
#include "net-policy.h"

using namespace std;

void ipv4CidrToIp(std::string cidr, std::string &ip, int &mask)
{
    struct in_addr addr;
    uint32_t uzIpaddr, uzMask;
    size_t index;
    string sip, smask;
    smask = "32";
    sip = cidr;
    index = cidr.find("/");
    if(index != string::npos)
    {
        sip = cidr.substr(0, index);
        smask = cidr.substr(index + 1);
    }
    uzIpaddr = ntohl(inet_addr(sip.c_str()));
    uzMask   = atoi(smask.c_str());
    mask     = uzMask;
    uzMask   = ~0 << (32 - uzMask);
    /*count network address*/
    uzIpaddr &= uzMask;
    addr.s_addr = htonl(uzIpaddr);
    ip = inet_ntoa(addr);
}

std::string ipv4CidrToIp(std::string ip, int mask)
{
    struct in_addr addr;
    uint32_t uzIpaddr, uzMask;
    uzIpaddr = ntohl(inet_addr(ip.c_str()));
    uzMask   = ~0 << (32 - mask);
    /*count network address*/
    uzIpaddr &= uzMask;
    addr.s_addr = htonl(uzIpaddr);
    return inet_ntoa(addr);
}


FiveTuple::FiveTuple() { this->InitTuple(); }
FiveTuple::~FiveTuple() {}

void FiveTuple::InitTuple()
{
    this->proto     = 0;
    this->totLen    = 0;
    this->srcPort   = 0;
    this->dstPort   = 0;
    this->uzSrcAddr = 0;
    this->uzDstAddr = 0;
    this->srcAddr   = "";
    this->dstAddr   = "";
}
void FiveTuple::PrintData(std::string key, int level)
{
    if(level < gzLogLevel) return;
    if(this->srcPort == 53 || this->dstPort == 53) return;
    if(this->srcAddr == "127.0.0.1" || this->dstAddr == "127.0.0.1") return;
    LOG_D("key : %s, five tuple -> proto : %d, %s:%d --> %s:%d", key.c_str(), this->proto, this->srcAddr.c_str(), this->srcPort, this->dstAddr.c_str(), this->dstPort);
}

NFQ_RES_INFO::NFQ_RES_INFO() {}
NFQ_RES_INFO::~NFQ_RES_INFO() {}

void NFQ_RES_INFO::Init()
{
    this->pid       = 0;
    this->inputFd   = 0;
    this->outputFd  = 0;
    this->podId     = 0;
    this->pollFd    = 0;
    this->inputQue  = nullptr;
    this->outputQue = nullptr;
    this->inputCb   = nullptr;
    this->outputcb  = nullptr;
    //nf conntrack
    this->nfct      = nullptr;
    this->nfctCb    = nullptr;
    this->nfctHd    = nullptr;
    this->nfctCbHd  = nullptr;
}

/*释放资源*/
void NFQ_RES_INFO::FreeResource(int efd)
{
    struct epoll_event ev;
    struct nfq_q_handle *qh = NULL;

    /*close input fd*/
    if(this->inputFd > 0)
    {
        ev.data.fd = this->inputFd;
        epoll_ctl(efd, EPOLL_CTL_DEL, this->inputFd, &ev);
        close(this->inputFd);
    }
    /*close output fd*/
    if(this->outputFd > 0)
    {
        ev.data.fd = this->outputFd;
        epoll_ctl(efd, EPOLL_CTL_DEL, this->outputFd, &ev);
        close(this->outputFd);
    }
    /*destroy input queue*/
    if(this->inputQue)
    {
        qh = (struct nfq_q_handle *)this->inputQue;
        nfq_close(qh->h);
        nfq_destroy_queue(qh);
    }
    /*destroy output queue*/
    if(this->outputQue)
    {
        qh = (struct nfq_q_handle *)this->outputQue;
        nfq_close(qh->h);
        nfq_destroy_queue(qh);
    }
    if(this->inputCb) delete (RCV_EPOLL_CB *)this->inputCb;
    if(this->outputcb) delete (RCV_EPOLL_CB *)this->outputcb;
    if(this->nfct) nfct_destroy((NF_CONNTRACK *)this->nfct);
    if(this->nfctCb) nfct_destroy((NF_CONNTRACK *)this->nfctCb);
    if(this->nfctHd) nfct_close((struct nfct_handle *)this->nfctHd);
    if(this->nfctCbHd) nfct_close((struct nfct_handle *)this->nfctCbHd);
    /*print debug log*/
    LOG_I("free nfqueue resource, pid : %d", this->pid);
}

RuleDetail::RuleDetail() {}
RuleDetail::~RuleDetail() {}

/*添加端口*/
void RuleDetail::AddPortsCfg(RULE_PORT &port) { this->vPorts.push_back(port); }
/*清除端口配置*/
void RuleDetail::ClearPortsCfg() { this->vPorts.clear(); }
/*生成用于匹配的策略*/
std::string RuleDetail::CreateRuleKey(int &mask)
{
    string key, ip;
    char buff[128] = {0};
    switch (this->direction)
    {
        case DIR_INGRESS:
            ipv4CidrToIp(this->srcIp, ip, mask);
            /*create key*/
            sprintf(buff, "%d-%d-%s-%s", this->priority, this->proto, ip.c_str(), this->dstIp.c_str());
            break;
        default:
            ipv4CidrToIp(this->dstIp, ip, mask);
            /*create key*/
            sprintf(buff, "%d-%d-%s-%s", this->priority, this->proto, this->srcIp.c_str(), ip.c_str());
            break;
    }
    key = buff;
    /*return*/
    return key;
}

/*匹配策略详情*/
bool RuleDetail::MatchRuleDetail(FiveTuple &tuple, FLOW_DIR dir)
{
    int p = 0;
    bool bIsMatch = false;
    uint8_t protocol = tuple.proto;
    /*处理ICMP协议*/
    if(protocol == IPPROTO_ICMP) protocol = this->proto;
    /*匹配协议*/
    if(!((this->proto == 0) || (protocol == this->proto))) return false;
    /*匹配ICMP协议*/
    if((this->vPorts.size() == 0) || (tuple.proto == IPPROTO_ICMP)) bIsMatch = true;
    /*匹配端口*/
    for(p = 0; p < (int)this->vPorts.size(); p++)
    {
        if(this->vPorts.at(p).endPort == 0)
        {
            bIsMatch = true;
            break;
        }
        /*check port rang*/
        if(tuple.dstPort > this->vPorts.at(p).endPort) continue;
        /*check min port*/
        if(tuple.dstPort < this->vPorts.at(p).port) continue;
        /*set match true*/
        bIsMatch = true;
        break;
    }
    /*判断是否匹配成功*/
    if(!bIsMatch) return false;
    /*print debug log*/
    LOG_D("match %s name : %s, dir : %d, action : %d, priority : %d, proto : %d, ip : %s <--> %s port : %d ~ %d",
        (dir == DIR_INGRESS) ? "ingress" : "egress", this->policyKey.c_str(), this->direction, this->action, this->priority, 
        this->proto, this->srcIp.c_str(), this->dstIp.c_str(), this->vPorts.at(p).port, this->vPorts.at(p).endPort);
    /*return*/
    return true;
}

/*打印策略详情*/
void RuleDetail::PrintRuleDetail(std::string desc)
{
    char buf[128];
    std::string ports = "";
    /*log level*/
    if(gzLogLevel < 2) return;
    /*format port*/
    for(int i = 0; i < (int)this->vPorts.size(); i++)
    {
        memset(buf, 0, sizeof(buf));
        sprintf(buf, "%d ~ %d", this->vPorts.at(i).port, this->vPorts.at(i).endPort);
        ports += buf;
        if((i + 1) < (int)this->vPorts.size()) ports += ",";
    }
    LOG_V("%s detail -> proto : %d, priority : %d, dir : %d, action : %d, name : %s, addr : %s -> %s, ports : %s", 
        desc.c_str(), this->proto, this->priority, this->direction, this->action, this->policyKey.c_str(), this->srcIp.c_str(), this->dstIp.c_str(), ports.c_str());
}

RuleGroup::RuleGroup() { this->Rules.clear(); }
RuleGroup::~RuleGroup() {}

/*增加策略详情信息*/
bool RuleGroup::AddRuleDetail(RuleDetail rule, RULE_PORT &stPort)
{
    /*clear ports*/
    rule.ClearPortsCfg();
    /*查询策略是否已经存在*/
    auto it = this->Rules.find(rule.policyKey);
    if(it == this->Rules.end())
    {
        /*print debug log*/
        LOG_D("create policy name : %s, action : %d, mutil port : %d ~ %d.", rule.policyKey.c_str(), rule.action, stPort.port, stPort.endPort);
        /*save policy port*/
        rule.AddPortsCfg(stPort);
        /*make shared*/
        auto detail = std::make_shared<RuleDetail>(rule);
        /*新增数据*/
        this->Rules[rule.policyKey] = detail;
        /*return*/
        return true;
    }
    /*value*/
    auto detail = it->second;
    /*add port config*/
    detail->AddPortsCfg(stPort);
    /*print debug log*/
    LOG_D("add policy name : %s, dir : %d, action : %d, mutil port : %d ~ %d, port num : %d", rule.policyKey.c_str(), rule.direction, rule.action, stPort.port, stPort.endPort, (int)detail->vPorts.size());
    /*print debug log*/
    detail->PrintRuleDetail("add");
    /*return*/
    return true;
}

/*删除匹配策略*/
void RuleGroup::DeleteRule(std::string policyName)
{
    auto it = this->Rules.find(policyName);
    if(it == this->Rules.end()) return;
    /*删除策略*/
    auto detail = it->second;
    /*打印需要删除的策略详情*/
    detail->PrintRuleDetail("delete");
    /*删除该策略*/
    this->Rules.erase(it);
}

/*匹配策略*/
bool RuleGroup::MatchRule(FiveTuple &tuple, RuleDetail &detail, FLOW_DIR dir)
{
    if(this->Rules.size() == 0) return false;
    /*遍历规则列表*/
    for(auto it = this->Rules.begin(); it != this->Rules.end(); it++)
    {
        detail = it->second;
        auto ret = detail.MatchRuleDetail(tuple, dir);
        if(ret) return true;
    }

    /*return*/
    return false;
}

/*获取规则数*/
size_t RuleGroup::GetRulesSize() { return this->Rules.size(); }


RuleChain::RuleChain() { this->Chain.clear(); }
RuleChain::~RuleChain() {}

/*获取规则表数据量*/
size_t RuleChain::RuleSize() { return this->Chain.size(); }

/*set dir*/
void RuleChain::SetRuleDir(FLOW_DIR direction) { this->dir = direction;}

/*清空规则*/
void RuleChain::RuleChainClear() { this->Chain.clear(); }

/*匹配规则*/
bool RuleChain::MatchRuleGroup(std::string &key, FiveTuple &tuple, RuleDetail &detail)
{
    /*match rule*/
    auto it = this->Chain.find(key);
    if(it == this->Chain.end()) return false;
    /*print debug log*/
    tuple.PrintData(key);
    /*match rule*/
    return it->second->MatchRule(tuple, detail, this->dir);
}

/*生成匹配规则,并保持到链上*/
int RuleChain::AddRuleToChain(std::string key, RuleDetail &policy, RULE_PORT &stPort)
{
    /*check key*/
    auto it = this->Chain.find(key);
    if(it == this->Chain.end())
    {
        auto rg = std::make_shared<RuleGroup>();
        if(rg == nullptr) RETURN_ERROR(2, "new memory failed by rule group.");
        /*print debug log*/
        LOG_D("create group to chain, policy name : %s, rule key : %s", policy.policyKey.c_str(), key.c_str());
        /*add rule*/
        auto ok = rg->AddRuleDetail(policy, stPort);
        if(!ok) RETURN_ERROR(5, "add policy detail failed.");
        /*add rule group*/
        this->Chain[key] = rg;
    }
    else
    {
        auto rg = it->second;
        if(rg == nullptr) RETURN_ERROR(8, "rule group is null, key : %s", key.c_str());
        /*add rule*/
        auto ok = rg->AddRuleDetail(policy, stPort);
        if(!ok) RETURN_ERROR(5, "update policy detail failed.");
        /*print debug log*/
        LOG_D("add group to chain, policy name : %s, rule key : %s, group size : %d", policy.policyKey.c_str(), key.c_str(), (int)rg->GetRulesSize());
    }
    /*return*/
    return 0;
}

/*从链上删除规则*/
void RuleChain::DeleteRuleFromChain(std::string pname, std::string ruleKey)
{
    auto it = this->Chain.find(ruleKey);
    if(it == this->Chain.end()) return;
    /*获取规则组*/
    auto group = it->second;
    if (group == nullptr) return;
    /*删除规则*/
    group->DeleteRule(pname);
    /*重新将规则添加到链上*/
    if(group->GetRulesSize() == 0)
    {
        /*打印调试日志*/
        LOG_D("delete group, policy name : %s, rule key : %s, dir : %d", pname.c_str(), ruleKey.c_str(), this->dir);
        /*从新将规则添加到链上*/
        this->Chain.erase(it);
    }
}


PolicyTree::PolicyTree() { this->Clear(); }
PolicyTree::~PolicyTree() {}


/*get size*/
int PolicyTree::GetTreeSize() { return (int)this->Tree.size(); }

/*clear*/
int PolicyTree::Clear()
{
    for(auto it = this->Tree.begin(); it != this->Tree.end(); it++)
    {
        auto value = it->second;
        if(value == nullptr) continue;
        delete value;
    }

    this->Tree.clear();
    this->RuleChainClear();
    return 0;
}

/*delete policy*/
int PolicyTree::DeletePolicyFromTree(std::string &name)
{
    /*find*/
    auto pit = this->Tree.find(name);
    if(pit == this->Tree.end()) RETURN_INFO(0, "can not find this key : [%s], dir : %d", name.c_str(), this->dir);
    /*remove policy*/
    this->Tree.erase(pit);
    /*get value*/
    auto rules = pit->second;
    if(rules == nullptr) RETURN_WARN(0, "policy information is null, name : %s, dir : %d", name.c_str(), this->dir);
    /*print debug log*/
    LOG_D("policy name : %s, rule numbers : %lu, dir : %d.", name.c_str(), rules->size(), this->dir);
    /*delete rule*/
    for(auto it = rules->begin(); it != rules->end(); it++)
    {
        auto key = it->first;
        auto value = it->second;
        /*print debug log*/
        LOG_D("delete policy, flow dir : %s, key : %s.", (value == DIR_INGRESS) ? "ingress" : "egress", key.c_str());
        /*删除策略下的规则*/
        this->DeleteRuleFromChain(name, key);
    }
    /*clear net policy*/
    rules->clear();
    delete rules;
    /*clear all*/
    if(this->Tree.size() == 0) return this->Clear();
    /*print debug log*/
    LOG_D("delete net policy name : %s, dir : %d", name.c_str(), this->dir);
    /*return*/
    return 0;
}

/*将规则添加到链上*/
int PolicyTree::AddPolicyToChain(RuleDetail &policy, RULE_PORT &stPort, int &zMask)
{
    std::unordered_map<std::string, FLOW_DIR>* ruleMap;
    /*query policy*/
    auto it = this->Tree.find(policy.policyKey);
    if(it == this->Tree.end())
    {
        ruleMap = new std::unordered_map<std::string, FLOW_DIR>;
        if(ruleMap == nullptr) RETURN_ERROR(2, "new memory failed when add policy.");
        /*insert data*/
        auto ret = this->Tree.insert(std::make_pair(policy.policyKey, ruleMap));
        if(!ret.second) RETURN_ERROR(3, "insert policy name to map failed when add policy.");
        /*print debug log*/
        LOG_D("create new policy : [%s]", policy.policyKey.c_str());
    }
    else
    {
        ruleMap = it->second;
    }
    /*check rule map*/
    if(ruleMap == nullptr) RETURN_ERROR(12, "rule map is nil.");
    /*create policy rule key*/
    auto key = policy.CreateRuleKey(zMask);
    /*写入匹配规则*/
    auto ret = this->AddRuleToChain(key, policy, stPort);
    if(ret != 0) return ret;
    /*insert key*/
    ruleMap->insert(std::make_pair(key, policy.direction));
    /*return*/
    return 0;
}

PolicyRule::PolicyRule() { this->ClearCfg(); }
PolicyRule::~PolicyRule() {}

/*清除优先级和子网掩码*/
int PolicyRule::ClearCfg()
{
    this->MaskCidr.clear();
    this->Priority.clear();
    this->MaskCidr.insert(32);
    /*init map*/
    this->InputTree.Clear();
    this->OutputTree.Clear();
    /*set rule direction*/
    this->InputTree.SetRuleDir(DIR_INGRESS);
    this->OutputTree.SetRuleDir(DIR_EGRESS);
    return 0;
}

/*通过五元组生成规则*/
void PolicyRule::CreateRuleKeyByTuple(FiveTuple &tuple, FLOW_DIR dir, std::vector<std::string> &value)
{
    char buff[128] = {0};
    char data[128] = {0};
    std::vector<std::string> srcaddr, dstaddr;
    /*init*/
    value.clear();
    /*create key*/
    for(auto it = this->Priority.begin(); it != this->Priority.end(); ++it)
    {
        for(auto iter = this->MaskCidr.begin(); iter != this->MaskCidr.end(); ++iter)
        {
            /*clear data*/
            dstaddr.clear();
            srcaddr.clear();
            switch (dir)
            {
                case DIR_INGRESS:
                    srcaddr.push_back("0.0.0.0");
                    srcaddr.push_back(ipv4CidrToIp(tuple.srcAddr, *iter));
                    dstaddr.push_back(tuple.dstAddr);
                    break;
                default:
                    srcaddr.push_back(tuple.srcAddr);
                    dstaddr.push_back("0.0.0.0");
                    dstaddr.push_back(ipv4CidrToIp(tuple.dstAddr, *iter));
                    break;
            }
            //list priority
            for(size_t i = 0; i < srcaddr.size(); i++)
            {
                for(size_t j = 0; j < dstaddr.size(); j++)
                {
                    memset(buff, 0, sizeof(buff));
                    sprintf(buff, "%d-%d-%s-%s", *it, tuple.proto, srcaddr.at(i).c_str(), dstaddr.at(j).c_str());
                    /*save key*/
                    value.push_back(buff);
                    /*print debug log*/
                    //tuple.PrintData(buff, 2);
                    /*all protocol*/
                    memset(data, 0, sizeof(data));
                    sprintf(data, "%d-0-%s-%s", *it, srcaddr.at(i).c_str(), dstaddr.at(j).c_str());
                    /*save key*/
                    value.push_back(data);
                    /*print debug log*/
                    //tuple.PrintData(data, 2);
                }
            }
        }
    }
    /*print debug log*/
    LOG_T("create rule key num : %lu, priority size : %lu, mark size : %lu.", value.size(), this->Priority.size(), this->MaskCidr.size());
}

/*获取策略map*/
PolicyTree *PolicyRule::GetPolicyTree(FLOW_DIR dir)
{
    return (dir == DIR_INGRESS) ? &this->InputTree : &this->OutputTree;
}

/*打印日志*/
void PolicyRule::PrintPolicyLog()
{
    LOG_D("NetInput : %d, NetOutput : %d, input tree : %d, output tree : %d", (int)this->InputTree.RuleSize(), (int)this->OutputTree.RuleSize(), this->InputTree.GetTreeSize(), this->OutputTree.GetTreeSize());
}

/*添加优先级和子网掩码*/
void PolicyRule::AddMaskAndPriority(int priority, int mask)
{
    /*save priority*/
    this->Priority.insert(priority);
    /*save cidr*/
    if((mask > 0) && (mask <= 32)) this->MaskCidr.insert(mask);
}

/*将规则添加到链上*/
int PolicyRule::AddPolicyToTree(RuleDetail &policy, RULE_PORT &stPort)
{
    int zMask = 0;
    /*get policy tree*/
    auto tree = this->GetPolicyTree(policy.direction);
    /*return*/
    auto ret = tree->AddPolicyToChain(policy, stPort, zMask);
    if(ret != 0) RETURN_ERROR(ret, "add policy to chain failed.");
    /*save priority*/
    this->AddMaskAndPriority(policy.priority, zMask);
    /*return*/
    return 0;
}

/*删除指定策略*/
int PolicyRule::DeletePolicy(FLOW_DIR dir, std::string name)
{
   auto tree = this->GetPolicyTree(dir);
    /*return*/
    return tree->DeletePolicyFromTree(name);
}

/*获取所有规则配置*/
cJSON *PolicyRule::GetAllConfig()
{
    NFQ_RES_INFO *res;
    cJSON *containers = nullptr, *tcp = nullptr, *r, *item;
    cJSON *config = nullptr, *inrule = nullptr, *outrule = nullptr;

    tcp = cJSON_CreateObject();
    config = cJSON_CreateObject();
    inrule = cJSON_CreateArray();
    outrule = cJSON_CreateArray();
    containers = cJSON_CreateArray();
    auto stat = connectionManager.stat();
    if(!config || !outrule || !inrule || !tcp || !containers) GOTO_ERROR(err, "create json object failed.");

    for(auto it = this->InputTree.Chain.begin(); it != this->InputTree.Chain.end(); it++)
    {
        auto rule = it->second;
        if(rule == nullptr) continue;

        for(auto rd = rule->Rules.begin(); rd != rule->Rules.end(); rd++)
        {
            r = cJSON_CreateObject();
            if(!r) GOTO_ERROR(err, "create json object failed.");

            cJSON_AddStringToObject(r, "policy_name", rd->second->policyKey.c_str());
            cJSON_AddNumberToObject(r, "priority", rd->second->priority);
            cJSON_AddStringToObject(r, "direction", utility::directionString(rd->second->direction).data());
            cJSON_AddStringToObject(r, "action", utility::actionString(rd->second->action).data());
            cJSON_AddStringToObject(r, "protocol", utility::protocolString(rd->second->proto).data());
            cJSON_AddNumberToObject(r, "protocol_int", rd->second->proto);
            cJSON_AddStringToObject(r, "from_address", rd->second->srcIp.c_str());
            cJSON_AddStringToObject(r, "to_address", rd->second->dstIp.c_str());
            cJSON_AddItemToArray(inrule, r);
        }
    }
    cJSON_AddItemToObject(config, "inbound_rules", inrule);

    for (auto it = this->OutputTree.Chain.begin(); it != this->OutputTree.Chain.end(); it++)
    {
        auto rule = it->second;
        if(rule == nullptr) continue;

        for(auto rd = rule->Rules.begin(); rd != rule->Rules.end(); rd++)
        {
            r = cJSON_CreateObject();
            if(!r) GOTO_ERROR(err, "create json object failed.");

            cJSON_AddStringToObject(r, "policy_name", rd->second->policyKey.c_str());
            cJSON_AddNumberToObject(r, "priority", rd->second->priority);
            cJSON_AddStringToObject(r, "direction", utility::directionString(rd->second->direction).data());
            cJSON_AddStringToObject(r, "action", utility::actionString(rd->second->action).data());
            cJSON_AddStringToObject(r, "protocol", utility::protocolString(rd->second->proto).data());
            cJSON_AddNumberToObject(r, "protocol_int", rd->second->proto);
            cJSON_AddStringToObject(r, "from_address", rd->second->srcIp.c_str());
            cJSON_AddStringToObject(r, "to_address", rd->second->dstIp.c_str());
            cJSON_AddItemToArray(outrule, r);
        }
    }
    cJSON_AddItemToObject(config, "outbound_rules", outrule);

    for (auto it = this->ResData.begin(); it != this->ResData.end(); it++)
    {
        res = it->second;
        if(res == nullptr) continue;

        item = cJSON_CreateObject();
        if(!item) GOTO_ERROR(err, "create json object failed.");
        cJSON_AddNumberToObject(item, "pid", res->pid);
        cJSON_AddNumberToObject(item, "pod_id", res->podId);
        cJSON_AddItemToArray(containers,  item);
    }
    cJSON_AddItemToObject(config, "containers",containers);

    cJSON_AddNumberToObject(tcp, "tcp_connection", stat.tcp_conn_);
    cJSON_AddItemToObject(config, "tcp",tcp);

    return config;

err:
    if(tcp) cJSON_Delete(tcp);
    if(config) cJSON_Delete(config);
    if(inrule) cJSON_Delete(inrule);
    if(outrule) cJSON_Delete(outrule);
    if(containers) cJSON_Delete(containers);
    return nullptr;
}


NfQueData::NfQueData() { this->ResData.clear(); }
NfQueData::~NfQueData() {}

/*create nfqueue resource*/
int NfQueData::NewNfQueRes(uint64_t pid, NFQ_RES_INFO *res)
{
    auto ret = this->ResData.insert(make_pair(pid, res));
    if(!ret.second) RETURN_ERROR(-2, "save nfq resource data failed.");
    /*return*/
    return 0;
}

/*delete nfqueue resource*/
int NfQueData::DeleteNfQueRes(int efd, uint64_t pid)
{
    auto it = this->ResData.find(pid);
    if(it == this->ResData.end()) return 0;
    /*erase key*/
    this->ResData.erase(it);
    /*delete memory*/
    if(it->second != nullptr)
    {
        it->second->FreeResource(efd);
        /*free memory*/
        delete it->second;
    }
    /*return*/
    return 0;
}

/*get nfqueue resource*/
NFQ_RES_INFO *NfQueData::GetNfqRes(uint64_t pid)
{
    auto it = this->ResData.find(pid);
    if(it == this->ResData.end()) return nullptr;
    /*return*/
    return it->second;
}

/*clear nfqueue resource*/
void NfQueData::ClearNfQueResource(int efd)
{
    int ret;
    for (auto it = this->ResData.begin(); it != this->ResData.end(); it++)
    {
        /*set network namespace*/
        ret = SetNs(it->second->pid, (char *)BasePath);
        if (ret != 0) continue;
        /*print debug log*/
        LOG_D("destroy nfqueue, pid : %d.", it->second->pid);
        /*clear iptables rule*/
        ClearIptabelsRule();
        /*delete memory*/
        if(it->second == nullptr) continue;
        /*free nfque resource*/
        it->second->FreeResource(efd);
        /*free memory*/
        delete it->second;
    }
    /*clear map*/
    this->ResData.clear();
}
