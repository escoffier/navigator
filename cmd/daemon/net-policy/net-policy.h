#pragma once

#include <unordered_map>
#include <string>
#include <netinet/in.h>
#include "vector"
#include "cjson.h"
#include "libmnl/libmnl.h"
#include "libnetfilter_conntrack/libnetfilter_conntrack.h"
#include "libnetfilter_queue/libnetfilter_queue.h"

#define BasePath             ("/host")
#define NET_POLICY_UNIX      ("/var/run/heavy-agent/zero-trust.sock")
#define POST_NET_UNIX        ("/var/run/heavy-agent/zero-trust-post.sock")
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

/*epoll call function*/
typedef int32_t (*RcvCbFunc)(int32_t zRcvEvFd, int32_t fd, void *ptr);

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
    NET_INFO_MAX
} NET_DATA_TYPE;

typedef enum
{
    NET_DENY      = 0,
    NET_ALLOW     = 1,
    NET_ALLOW_RSP = 2,
    NET_ALLOW_REQ = 3,
    NET_DEFAULT   = 4,
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

typedef struct
{
    char proto;
    uint16_t totLen;
    uint16_t srcPort;
    uint16_t dstPort;
    uint32_t uzSrcAddr;
    uint32_t uzDstAddr;
    std::string srcAddr;
    std::string dstAddr;
} FIVE_TUPLE;

 struct NFQ_RES_INFO
{
    int pid = 0;
    int inputFd = 0;
    int outputFd = 0;
    uint64_t podId = 0;
    void *inputQue = NULL;
    void *outputQue = NULL;
    void *inputCb = NULL;
    void *outputcb = NULL;
    //nf conntrack
    void *nfct = NULL;
    void *nfctCb = NULL;
    void *nfctHd = NULL;
    void *nfctCbHd = NULL;
} ;

typedef struct
{
    int32_t fd;
    RcvCbFunc epollinfunc;/*epoll EPOLLIN*/
    NFQ_RES_INFO nfqres;
} RCV_EPOLL_CB;

typedef struct
{
    int  pid;//进程PID
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

struct RULE_DETAIL
{
    char proto;//协议
    int  priority;//权重
    int  addrType;//ipv4 OR ipv6
    FLOW_DIR direction; //流量策略方向
    NET_POLICY_RULE action;//策略
    std::vector<RULE_PORT> vPorts;//
    std::string policyKey;//策略主键
    std::string srcIp;//源地址
    std::string dstIp;//目的地址
};
