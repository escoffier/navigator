#ifndef NET_EBPF_USER_H
#define NET_EBPF_USER_H

#define LOG_ERROR(fmt, ...) {\
    printf("[ERROR] [line:%d] [%s] " fmt "\n", __LINE__, __FUNCTION__, ##__VA_ARGS__);\
}

#define LOG_PRINT(fmt, ...) {\
    printf("[INFO] [line:%d] [%s] " fmt "\n", __LINE__, __FUNCTION__, ##__VA_ARGS__);\
}

#define LOG_WARN(fmt, ...) {\
    printf("[WARN] [line:%d] [%s] " fmt "\n", __LINE__, __FUNCTION__, ##__VA_ARGS__);\
}

#define BREAK_ERROR(fmt, ...) {\
    printf("[WARN] [line:%d] [%s] " fmt "\n", __LINE__, __FUNCTION__, ##__VA_ARGS__);\
    break;\
}

#define LINK_ST_ESTABLISHED (1)
#define LINK_ST_LISTEN      (10)
#define RCV_ADDR            (1)
#define SND_ADDR            (2)
#define BasePath            ("/host")
#define DAEMON_UNIX         ("/tmp/setns.sock")
#define MATCH_SUCC          (1)
#define EBPF_SUCC           (1)

typedef unsigned char		UCHAR;
typedef unsigned short		USHORT;
typedef unsigned int		UINT;

enum
{
    DATA_SETNS      = 0,
    DATA_EBPF       = 1,
    DATA_FILTER     = 2,
    DATA_EBPF_STATE = 3,
};

typedef struct
{
    int  proto;
    int  dataType;
    int  pid;
    int  addrType;
    int  srcPort;
    int  dstPort;
    char srcIp[16];
    char dstIp[16];
} PidAssMnt;


extern int parse_get_ebpf_state(char *src, char *dst, int buflen);
extern int parse_filter_condition(char *buf);
extern char *lookup_ebpf_map();
extern int get_ebpf_state();
extern int ebpf_start();

#endif //NET_EBPF_USER_H