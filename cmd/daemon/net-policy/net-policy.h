#pragma once

#include <unordered_map>
#include <string>
#include <vector>
#include <set>
#include <netinet/in.h>
#include "vector"
#include "cjson.h"
#include "libmnl/libmnl.h"
#include "libnetfilter_conntrack/libnetfilter_conntrack.h"
#include "libnetfilter_queue/libnetfilter_queue.h"
#include "glog/logging.h"
#include "http/packet.hh"
#include "log.h"
#include "http/codec.h"
#include "http/connection.h"
#include "http/extension/log.h"
#include "http/filter.h"
#include "http/http_filter_factory.h"
#include "net/connection_manager.h"
#include "net/ip.h"
#include "net/utility.h"
#include "waf/plugin.h"
#include "policy/engine.h"
#include "admin/profile.h"
#include "utils.h"

#define BasePath             ("/host")
#define NET_POLICY_ADDR      ("127.0.0.1")
#define NET_POLICY_PORT      (9999)
#define POST_NET_PORT        (8888)
#define NF_MATCH_RULE        (6)

/* Responses from hook functions. 
#define NF_DROP 0
#define NF_ACCEPT 1
#define NF_STOLEN 2
#define NF_QUEUE 3
#define NF_REPEAT 4
#define NF_STOP 5
#define NF_MAX_VERDICT NF_STOP
*/

typedef struct nf_conntrack NF_CONNTRACK;
/*epoll call function*/
typedef int32_t (*RcvCbFunc)(int32_t zRcvEvFd, int32_t fd, void *ptr);
/*清除iptables配置*/
extern void ClearIptabelsRule();
extern int SetNs(int pid, char *basePath);
/*connection manager*/
extern net::ConnectionManager connectionManager;

typedef enum
{
    POD_PID  = 1, //pod up
    POD_DIE  = 2, //delete pod
    ADD_RULE = 3, //add rule
    DEL_RULE = 4, //delete rule
    RSP_ACK  = 5, //response
    POST_NET = 6, //deny post
    ADD_WAF_RULE = 7,//add waf rule
    DEL_WAF_RULE = 8,//delete waf rule
    HEAP_DUMP = 9,
    CONF_DUMP = 10,
    CONN_DUMP = 11,
    RESET     = 12,
    NODE_CFG  = 13,
    LOG_LEVEL = 14,
    NET_INFO_MAX
} NET_DATA_TYPE;

typedef enum
{
    NET_DENY      = 0,
    NET_ALLOW     = 1,
    NET_MARK      = 2,
    NET_ALLOW_RSP = 3,
    NET_ALLOW_REQ = 4,
    NET_DEFAULT   = 5,
    NET_POLICY_MAX
} NET_POLICY_RULE;

typedef enum
{
    DIR_INGRESS = 0,
    DIR_EGRESS  = 1,
    FLOW_DIR_MAX
} FLOW_DIR;

/*TCP/UDP伪首部*/
typedef struct
{
    uint32_t  saddr;
    uint32_t  daddr;
    uint8_t   placeholder;
    uint8_t   protocol;
    uint16_t  length;
} PSEUDO_HEADER;

typedef struct tcp_four_tuple
{
    uint32_t uzSrcAddr;
    uint32_t uzDstAddr;
    uint16_t usSrcPort;
    uint16_t usDstPort;
    /*override*/
    bool operator <(const tcp_four_tuple &other) const
	{
        /*compare source address*/
        if(uzSrcAddr < other.uzSrcAddr) {
             return true;
        } else if(uzSrcAddr > other.uzSrcAddr) {
            return false;
        }
        /*compare destination address*/
        if(uzDstAddr < other.uzDstAddr) {
            return true;
        } else if(uzDstAddr > other.uzDstAddr) {
            return false;
        }
        /*compare source port*/
        if(usSrcPort < other.usSrcPort) {
            return true;
        } else if(usSrcPort > other.usSrcPort) {
            return false;
        }
        /*compare destination port*/
        return usDstPort < other.usDstPort;
	}
} TCP_FOUR_TUPLE_V4;

class FiveTuple
{
public:
    uint8_t  proto;
    uint16_t totLen;
    uint16_t srcPort;
    uint16_t dstPort;
    uint32_t uzSrcAddr;
    uint32_t uzDstAddr;
    std::string srcAddr;
    std::string dstAddr;
public:
    FiveTuple();
    ~FiveTuple();
    void InitTuple();
    void PrintData(std::string, int level = 0);
};

 class NFQ_RES_INFO
{
public:
    int pid;
    int inputFd;
    int outputFd;
    int pollFd;
    void *inputQue;
    void *outputQue;
    void *inputCb;
    void *outputcb;
    //nf conntrack
    void *nfct;
    void *nfctCb;
    void *nfctHd;
    void *nfctCbHd;
    uint64_t podId;

public:
    NFQ_RES_INFO();
    ~NFQ_RES_INFO();
    /*初始化*/
    void Init();
    /*释放资源*/
    void FreeResource(int efd);
} ;

typedef struct
{
    int32_t fd;
    RcvCbFunc epollinfunc;/*epoll EPOLLIN*/
    NFQ_RES_INFO *nfqres;
} RCV_EPOLL_CB;

typedef struct
{
    int  pid;  //进程PID
    int  level;//日志级别
    uint64_t podId;
    std::string policyKey;
    std::string uuid;
    NET_DATA_TYPE msgType;//数据类型
} NET_CTRL_INFO;

typedef struct
{
    uint16_t endPort;//端口段上限
    uint16_t port;//端口段下限
    uint8_t  proto;//协议
} RULE_PORT;

struct HTTP_RULE_INFO
{
    uint8_t direction;
    NET_POLICY_RULE action;
    std::string host;
    std::string method;
    std::string path;
};

/*NFQUE*/
class NfQueData
{
public:
    std::unordered_map<uint64_t, NFQ_RES_INFO *> ResData;

public:
    NfQueData();
    ~NfQueData();
    /**/
    int NewNfQueRes(uint64_t pid, NFQ_RES_INFO *);
    /**/
    int DeleteNfQueRes(int efd, uint64_t pid);
    /**/
    NFQ_RES_INFO *GetNfqRes(uint64_t pid);
    /**/
    void ClearNfQueResource(int efd);
};

/*策略详情*/
class RuleDetail
{
public:
    uint8_t proto;//协议
    int  priority;//权重
    int  addrType;//ipv4 OR ipv6
    FLOW_DIR direction; //流量策略方向
    NET_POLICY_RULE action;//策略
    std::string ActionDsc;//策略描述
    std::string policyKey;//策略主键
    std::string srcIp;//源地址
    std::string dstIp;//目的地址
    std::vector<RULE_PORT> vPorts;//端口信息

public:
    RuleDetail();
    ~RuleDetail();
    // 拷贝构造函数，用于深拷贝
    RuleDetail(const RuleDetail& other)
    {
        proto = other.proto;
        priority = other.priority;
        addrType = other.addrType;
        direction = other.direction;
        action = other.action;
        ActionDsc = other.ActionDsc;
        policyKey = other.policyKey;
        srcIp = other.srcIp;
        dstIp = other.dstIp;
        // 对 vPorts 进行深拷贝
        vPorts.clear();
        for (const auto& port : other.vPorts) {
            vPorts.push_back(port);
        }
    }
    RuleDetail& operator=(const std::shared_ptr<RuleDetail>& other) {
        if (this == &(*other)) return *this;
        proto = other->proto;
        priority = other->priority;
        addrType = other->addrType;
        direction = other->direction;
        action = other->action;
        ActionDsc = other->ActionDsc;
        policyKey = other->policyKey;
        srcIp = other->srcIp;
        dstIp = other->dstIp;
        // 对 vPorts 进行深拷贝
        vPorts.clear();
        for (const auto& port : other->vPorts) {
            vPorts.push_back(port);
        }
        return *this;
    }
    /*添加端口*/
    void AddPortsCfg(RULE_PORT &);
    /*清除端口配置*/
    void ClearPortsCfg();
    /*生成用于匹配的策略*/
    std::string CreateRuleKey(int &mask);
    /*匹配策略详情*/
    bool MatchRuleDetail(FiveTuple &tuple, FLOW_DIR dir);
    /*打印策略详情*/
    void PrintRuleDetail(std::string desc);
};

/*策略组*/
class RuleGroup
{
public:
    std::unordered_map<std::string, std::shared_ptr<RuleDetail>> Rules;//key-策略名称
                                                                                                    
public:
    RuleGroup();
    ~RuleGroup();
    /*增加策略详情信息*/
    bool AddRuleDetail(RuleDetail, RULE_PORT &);
    /*删除匹配策略*/
    void DeleteRule(std::string policyName);
    /*匹配策略*/
    bool MatchRule(FiveTuple &tuple, RuleDetail &detail, FLOW_DIR dir);
    /*获取规则数*/
    size_t GetRulesSize();
};

/*链上规则表*/
class RuleChain
{
public:
    FLOW_DIR dir;
    std::unordered_map<std::string, std::shared_ptr<RuleGroup>> Chain;//key-匹配规则

public:
    RuleChain();
    ~RuleChain();
    /*获取规则表数据量*/
    size_t RuleSize();
    /*清空规则*/
    void RuleChainClear();
    /*set dir*/
    void SetRuleDir(FLOW_DIR);
    /*匹配规则*/
    bool MatchRuleGroup(std::string &key, FiveTuple &tuple, RuleDetail &detail);
    /*生成匹配规则,并保持到链上*/
    int AddRuleToChain(std::string key, RuleDetail &policy, RULE_PORT &stPort);
    /*从链上删除规则*/
    void DeleteRuleFromChain(std::string pname, std::string ruleKey);
};

/**/
class PolicyTree : public RuleChain
{
public:
    /*policy tree*/
    std::unordered_map<std::string, std::unordered_map<std::string, FLOW_DIR>*> Tree;

public:
    PolicyTree();
    ~PolicyTree();
    /*clear*/
    int Clear();
    /*get size*/
    int GetTreeSize();
    /*delete policy*/
    int DeletePolicyFromTree(std::string &name);
    /*将规则添加到链上*/
    int AddPolicyToChain(RuleDetail &policy, RULE_PORT &stPort, int &zMask);
};

/*网络策略详情*/
class PolicyRule : public NfQueData
{
public:
    int efd;
    /*Input上的策略规则*/
    /*Output上的策略规则*/
    PolicyTree InputTree;
    PolicyTree OutputTree;
    /*子网掩码*/
    std::set<int> MaskCidr;
    /*优先级*/
    std::set<int> Priority;

public:
    PolicyRule();
    ~PolicyRule();
    /*清除优先级和子网掩码*/
    int ClearCfg();
    /*删除指定策略*/
    int DeletePolicy(FLOW_DIR dir, std::string name);
    /*添加优先级和子网掩码*/
    void AddMaskAndPriority(int priority, int mask);
    /*将规则添加到链上*/
    int AddPolicyToTree(RuleDetail &policy, RULE_PORT &stPort);
    /*通过五元组生成规则*/
    void CreateRuleKeyByTuple(FiveTuple &tuple, FLOW_DIR dir, std::vector<std::string> &value);
    /*获取策略map*/
    PolicyTree *GetPolicyTree(FLOW_DIR dir);
    /*获取所有规则配置*/
    cJSON *GetAllConfig(std::string name);
    /*打印日志*/
    void PrintPolicyLog();
};