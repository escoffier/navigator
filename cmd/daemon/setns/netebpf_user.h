#ifndef NET_EBPF_USER_H
#define NET_EBPF_USER_H

#include <ifaddrs.h>
#include <net/if.h>

#define LOG_ERROR(fmt, ...) {\
    printf("[ERROR] [line:%d] [%s] [setns] " fmt "\n", __LINE__, __FUNCTION__, ##__VA_ARGS__);\
}

#define LOG_PRINT(fmt, ...) {\
    printf("[INFO] [line:%d] [%s] [setns] " fmt "\n", __LINE__, __FUNCTION__, ##__VA_ARGS__);\
}

#define LOG_WARN(fmt, ...) {\
    printf("[WARN] [line:%d] [%s] [setns] " fmt "\n", __LINE__, __FUNCTION__, ##__VA_ARGS__);\
}

#define LOG_DEBUG(fmt, ...) {\
    printf("[DEBUG] [line:%d] [%s] [setns] " fmt "\n", __LINE__, __FUNCTION__, ##__VA_ARGS__);\
}

#define RETURN_ERROR(ret, fmt, ...) {\
    printf("[WARN] [line:%d] [%s] [setns] " fmt "\n", __LINE__, __FUNCTION__, ##__VA_ARGS__);\
    return ret;\
}

#define BREAK_ERROR(fmt, ...) {\
    printf("[WARN] [line:%d] [%s] [setns] " fmt "\n", __LINE__, __FUNCTION__, ##__VA_ARGS__);\
    break;\
}

#define CONTINUE_ERROR(fmt, ...) {\
    printf("[WARN] [line:%d] [%s] [setns] " fmt "\n", __LINE__, __FUNCTION__, ##__VA_ARGS__);\
    continue;\
}

#define GOTO_ERROR(state, fmt, ...) {\
    printf("[WARN] [line:%d] [%s] [setns] " fmt "\n", __LINE__, __FUNCTION__, ##__VA_ARGS__);\
    goto state;\
}

#define LINK_ST_ESTABLISHED (1)
#define LINK_ST_LISTEN      (10)
#define RCV_ADDR            (1)
#define SND_ADDR            (2)
#define BasePath            ("/host")
#define DAEMON_UNIX         ("/tmp/setns.sock")
#define MATCH_IDLE          (0)
#define MATCH_SUCC          (1)
#define GET_DATA_SUCC       (2)
#define EBPF_SUCC           (1)

#define MAC_ADDRSTRLEN      (18)
#define BUF_SIZE            (8192)
#define COMM_SIZE           (64)

typedef unsigned char		UCHAR;
typedef unsigned short		USHORT;
typedef unsigned int		UINT;
typedef unsigned long       ULONG;

enum
{
    DATA_SETNS        = 0,
    DATA_EBPF         = 1,
    DATA_FILTER       = 2,
    DATA_EBPF_STATE   = 3,
    DATA_HOST_GATEWAY = 4,
    DATA_CONTAINER    = 5,
};

typedef struct
{
    int  proto;
    int  dataType;
    int  pid;
    int  addrType;
    int  srcPort;
    int  dstPort;
    char srcIp[INET6_ADDRSTRLEN];
    char dstIp[INET6_ADDRSTRLEN];
} PidAssMnt;

typedef struct
{
    u_int dstAddr;
    u_int srcAddr;
    u_int gateWay;
    char  ifName[IF_NAMESIZE];
} ROUTE_INFO;

typedef struct
{
    char gateway[INET6_ADDRSTRLEN];
    char ifName[IF_NAMESIZE];
} DEFAULT_ROUTE;

typedef struct
{
    char ipv4[INET_ADDRSTRLEN];
    char ipv6[INET6_ADDRSTRLEN];
    char mac[MAC_ADDRSTRLEN];
    char ifName[IF_NAMESIZE];
} IF_INFO;

typedef struct
{
    int  pid;
    char comm[COMM_SIZE];
    char starttime[COMM_SIZE];
} PROC_INFO;

typedef struct
{
    int port;
    int proto;
} LISTEN_PORT;

typedef struct
{
    void *data;
    int  length;
    int  cap;
} DATA_HEAD;

extern int parse_get_ebpf_state(char *src, char *dst, int buflen);
extern int parse_filter_condition(char *buf);
extern char *lookup_ebpf_map();
extern int get_ebpf_state();
extern int ebpf_start();

//
extern char *get_container_info();
extern char *encode_gateway(DATA_HEAD *data);
extern int get_gateway(DATA_HEAD *data);
extern int get_sub_process(int pid, char *pcBasePath, int spid[], int *num);
extern int get_process_starttime(int pid, char *pcBasePath, char *dst);
extern int get_process_user(int pid, char *pcBasePath, char *dst);
extern int get_if_name(DATA_HEAD *data);
extern int get_dev_name(DATA_HEAD *data, char *pcBasePath);
extern int get_default_gateway(DATA_HEAD *data, char *pcBasePath);
extern int get_listen_port(DATA_HEAD *data, char *pcBasePath);

#endif //NET_EBPF_USER_H
