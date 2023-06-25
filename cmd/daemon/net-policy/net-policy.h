#ifndef _NET_POLICY_H_
#define _NET_POLICY_H_

#include <map>
#include <string>

#ifdef  __cplusplus
extern "C" {
#endif

#include <netinet/in.h>
#include "cjson.h"
#include "libmnl/libmnl.h"
#include "libnetfilter_conntrack/libnetfilter_conntrack.h"
#include "libnetfilter_queue/libnetfilter_queue.h"

#define DEBUG_LOG 1

#define LOG_E(fmt, ...) {\
    fprintf(stderr, "[ERROR] [line:%d] [%s] [policy] " fmt "\n", __LINE__, __FUNCTION__, ##__VA_ARGS__);\
}

#define LOG_I(fmt, ...) {\
    fprintf(stderr, "[INFO] [line:%d] [%s] [policy] " fmt "\n", __LINE__, __FUNCTION__, ##__VA_ARGS__);\
}

#if DEBUG_LOG
#define LOG_D(fmt, ...) {\
    fprintf(stderr, "[DEBUG] [line:%d] [%s] [policy] " fmt "\n", __LINE__, __FUNCTION__, ##__VA_ARGS__);\
}
/*
#define LOG_V(fmt, ...) {\
    fprintf(stderr, "[VERBOSE] [line:%d] [%s] [policy] " fmt "\n", __LINE__, __FUNCTION__, ##__VA_ARGS__);\
}
*/
#define LOG_V(fmt, ...) ((void)0);

#else
#define LOG_D(fmt, ...) ((void)0);
#define LOG_V(fmt, ...) ((void)0);
#endif

#define LOG_W(fmt, ...) {\
    fprintf(stderr, "[WARN] [line:%d] [%s] [policy] " fmt "\n", __LINE__, __FUNCTION__, ##__VA_ARGS__);\
}

#define RETURN_ERROR(ret, fmt, ...) {\
    fprintf(stderr, "[ERROR] [line:%d] [%s] [policy] " fmt "\n", __LINE__, __FUNCTION__, ##__VA_ARGS__);\
    return ret;\
}

#define RETURN_WARN(ret, fmt, ...) {\
    fprintf(stderr, "[WARN] [line:%d] [%s] [policy] " fmt "\n", __LINE__, __FUNCTION__, ##__VA_ARGS__);\
    return ret;\
}

#define BREAK_ERROR(fmt, ...) {\
    fprintf(stderr, "[ERROR] [line:%d] [%s] [policy] " fmt "\n", __LINE__, __FUNCTION__, ##__VA_ARGS__);\
    break;\
}

#define CONTINUE_ERROR(fmt, ...) {\
    fprintf(stderr, "[ERROR] [line:%d] [%s] [policy] " fmt "\n", __LINE__, __FUNCTION__, ##__VA_ARGS__);\
    continue;\
}

#define CONTINUE_WARN(fmt, ...) {\
    fprintf(stderr, "[WARN] [line:%d] [%s] [policy] " fmt "\n", __LINE__, __FUNCTION__, ##__VA_ARGS__);\
    continue;\
}

#define GOTO_ERROR(state, fmt, ...) {\
    fprintf(stderr, "[ERROR] [line:%d] [%s] [policy] " fmt "\n", __LINE__, __FUNCTION__, ##__VA_ARGS__);\
    goto state;\
}

#define BasePath             ("/host")
#define NET_POLICY_UNIX      ("/var/run/zero-trust.sock")
#define POST_NET_UNIX        ("/var/run/zero-trust-post.sock")
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
    NET_INFO_MAX
} NET_DATA_TYPE;

typedef enum
{
    NET_DENY    = 0,
    NET_ALLOW   = 1,
    NET_DEFAULT = 2,
    NET_POLICY_MAX
} NET_POLICY_RULE;

typedef enum
{
    DIR_INGRESS = 0,
    DIR_EGRESS  = 1,
    FLOW_DIR_MAX
} FLOW_DIR;

typedef struct
{
    char proto;
    uint16_t srcPort;
    uint16_t dstPort;
    std::string srcAddr;
    std::string dstAddr;
} FIVE_TUPLE;

typedef struct
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
} NFQ_RES_INFO;

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
    NET_DATA_TYPE msgType;//数据类型
} NET_CTRL_INFO;

typedef struct
{
    uint16_t endPort;//端口段上限
    uint16_t port;//端口段下限
    uint8_t  proto;//协议
} RULE_PORT;

typedef struct 
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
} RULE_DETAIL;

#ifdef  __cplusplus
}
#endif  /* end of __cplusplus */

#endif //_NET_POLICY_H_
