#define _GNU_SOURCE #required for NI_NUMERICHOST
#include <arpa/inet.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <error.h>
#include <errno.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <fcntl.h>
#include <linux/rtnetlink.h>
//
#include "netebpf_user.h"

static int ParseNetRawData(char *data, char netdata[6][33])
{
    int ret, i = 0, index = 0;
    char *str, *p, tmp[1024] = {0};
    //check argument
    if(!data) return -2;
    //tmp init
    memset(tmp, 0, sizeof(tmp));
    memcpy(tmp, data, sizeof(tmp));
    //format data
    str = strtok(tmp, " ");
    while(str)
    {
        switch(i++)
        {
            case 1:
                p = strchr(str, ':');
                if(p == NULL) break;
                memset(netdata[index], 0, sizeof(netdata[index]));
                memcpy(netdata[index++], str, p - str);
                memset(netdata[index], 0, sizeof(netdata[index]));
                strcpy(netdata[index++], p + 1);
                break;
            case 2:
                p = strchr(str, ':');
                if(p == NULL) break;
                memset(netdata[index], 0, sizeof(netdata[index]));
                memcpy(netdata[index++], str, p - str);
                memset(netdata[index], 0, sizeof(netdata[index]));
                strcpy(netdata[index++], p + 1);
                break;
            case 3:
                memset(netdata[index], 0, sizeof(netdata[index]));
                strcpy(netdata[index++], str);
                break;
            case 9:
                memset(netdata[index], 0, sizeof(netdata[index]));
                strcpy(netdata[index++], str);
                break;
            default:
                break;
        }
        str = strtok(NULL, " ");
    }
    //check index
    if(index != 6) RETURN_ERROR(-1, "format net raw data failed! %s.", tmp);

    return 0;
}

static int ParseRouteRawData(char *data, char *name, ULONG *pulDst, ULONG *pulGateway)
{
    int ret, i = 0, index = 0;;
    char devname[64];
    unsigned long d, g, m;
    int flgs, ref, use, metric, mtu, win, ir;
    //check argument
    if(!data || !name || !pulDst || !pulGateway) return -2;
    //format data
    ret = sscanf(data, "%63s%lx%lx%X%d%d%d%lx%d%d%d", devname, &d, &g, &flgs, &ref, &use, &metric, &m, &mtu, &win, &ir);
    if(ret != 11) RETURN_ERROR(-1, "format data failed, %s, err : %s.", data, strerror(errno));
    //save data
    memcpy(name, devname, sizeof(devname));
    *pulDst = d;
    *pulGateway = g;
    return 0;
}

static int HexToDec(char *data)
{
    if(!data) return 0;
    return strtol(data, NULL, 16);
}

//read netlink message
static int ReadNetLinkMsg(int fd, char *bufPtr, int seqNum, int pId)
{
    struct nlmsghdr *nlHdr;
    int length = 0, msgLen = 0;

    do
    {
        //收到内核的应答
        length = recv(fd, bufPtr, BUF_SIZE - msgLen, 0);
        if (length <= 0) GOTO_ERROR(err, "read netlink data failed, fd : %d, %s.", fd, strerror(errno));
        //msg
        nlHdr = (struct nlmsghdr *)bufPtr;
        //检查header是否有效
        if ((NLMSG_OK(nlHdr, length) == 0) || (nlHdr->nlmsg_type == NLMSG_ERROR)) GOTO_ERROR(err, "recieved packet is error.");

        if (nlHdr->nlmsg_type == NLMSG_DONE) break;
        //
        bufPtr += length;
        msgLen += length;
        //
        if ((nlHdr->nlmsg_flags & NLM_F_MULTI) == 0) break;

    } while ((nlHdr->nlmsg_seq != seqNum) || (nlHdr->nlmsg_pid != pId));

    return msgLen;

err:
    return -1;
}

//分析返回的路由信息
static int ParseRoutes(struct nlmsghdr *nlHdr, ROUTE_INFO *rtInfo)
{
    struct rtmsg *rtMsg;
    struct rtattr *rtAttr;
    int rtLen;
    rtMsg = (struct rtmsg *)NLMSG_DATA(nlHdr);

    // If the route is not for AF_INET or does not belong to main routing table
    // then return.
    if ((rtMsg->rtm_family != AF_INET) || (rtMsg->rtm_table != RT_TABLE_MAIN))  return -1;
    //
    rtAttr = (struct rtattr *)RTM_RTA(rtMsg);
    rtLen = RTM_PAYLOAD(nlHdr);
    //
    for (; RTA_OK(rtAttr, rtLen); rtAttr = RTA_NEXT(rtAttr, rtLen))
    {
        switch (rtAttr->rta_type)
        {
        case RTA_OIF:
            if_indextoname(*(int *)RTA_DATA(rtAttr), rtInfo->ifName);
            break;
        case RTA_GATEWAY:
            rtInfo->gateWay = *(u_int *)RTA_DATA(rtAttr);
            break;
        case RTA_PREFSRC:
            rtInfo->srcAddr = *(u_int *)RTA_DATA(rtAttr);
            break;
        case RTA_DST:
            rtInfo->dstAddr = *(u_int *)RTA_DATA(rtAttr);
            break;
        }
    }
    //default gateway
    if (rtInfo->dstAddr == 0) return 0;

    return -1;
}

char *DeleteSpace(char *pcSrcData)
{
    int	len, k, i;
    if(!pcSrcData) return pcSrcData;

    len	= strlen(pcSrcData);
    k =	0;
    for	(i = 0; i < len; i++)
    {
        if((pcSrcData[i] !=	' ') && (pcSrcData[i] != '\n'))
        {
            pcSrcData[k] = pcSrcData[i];
            k++;
        }
    }
    pcSrcData[k] = 0;
    return pcSrcData;
}

int get_default_gateway(DATA_HEAD *data, char *pcBasePath)
{
    FILE *fp = NULL;
    ULONG ulDstAddr, ulGateway;
    int ret, arrlen, lineNum = 0;
    DEFAULT_ROUTE *pstRoute;
    char *dstip, ifname[64];
    char path[128] = {0};
    char buff[1024] = {0};
    struct in_addr in;
    //check argument
    if(!data || !pcBasePath) return -1;
    //data init
    data->length = 0;
    data->cap    = 8;
    //array len
    arrlen     = data->cap * sizeof(DEFAULT_ROUTE);
    data->data = (void *)malloc(arrlen);
    if(!data->data) RETURN_ERROR(1, "malloc memory failed, %s.", strerror(errno));
    memset(data->data, 0, sizeof(arrlen));
    //process children path
    sprintf(path, "%s/proc/net/route", pcBasePath);
    //open path
    fp = fopen(path, "r");
    if(!fp) RETURN_ERROR(-1,  "open tcp file %s failed, %s.", path, strerror(errno));
    //read lines
    while (!feof(fp))
    {
        memset(buff, 0, sizeof(buff));
        fgets(buff, sizeof(buff) - 1, fp);
        if((lineNum++) == 0) continue;
        //init
        memset(ifname, 0, sizeof(ifname));
        //LOG_PRINT("%s", buf);
        ret = ParseRouteRawData(buff, ifname, &ulDstAddr, &ulGateway);
        if(ret != 0) CONTINUE_ERROR("parse route raw data failed.");
        //check data
        if(data->length >= data->cap) BREAK_ERROR("get listen port is full.");
        //destination
        if(ulDstAddr != 0) break;
        //save data
        pstRoute  = (DEFAULT_ROUTE *)data->data;
        pstRoute += data->length++;
        //init
        memset(pstRoute, 0, sizeof(DEFAULT_ROUTE));
        //if name
        memcpy(pstRoute->ifName, ifname, strlen(ifname));
        //gateway
        in.s_addr = ulGateway;
        dstip = inet_ntoa(in);
        memcpy(pstRoute->gateway, dstip, strlen(dstip));
    }
    fclose(fp);
    //check result
    if(data->length == 0) RETURN_ERROR(-1, "get default gateway failed.");
    return 0;
err:
    if(fp) fclose(fp);
    return -1;
}

int get_gateway(DATA_HEAD *data)
{
    struct nlmsghdr *nlMsg;
    struct rtmsg *rtMsg;
    ROUTE_INFO rtInfo, *pstRtInfo;
    char msgBuf[BUF_SIZE];
    int sock = 0, ret, len, msgSeq = 0, arrlen;
    //check argument
    if(!data) return -1;
    //data init
    data->length = 0;
    data->cap    = 8;
    //array len
    arrlen     = data->cap * sizeof(ROUTE_INFO);
    data->data = (void *)malloc(arrlen);
    if(!data->data) RETURN_ERROR(1, "malloc memory failed, %s.", strerror(errno));
    memset(data->data, 0, sizeof(arrlen));
    //
    sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if (sock <= 0) GOTO_ERROR(err, "create netlink socket failed, %s.", strerror(errno));

    memset(msgBuf, 0, BUF_SIZE);
    nlMsg = (struct nlmsghdr *)msgBuf;
    rtMsg = (struct rtmsg *)NLMSG_DATA(nlMsg);
    nlMsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)); // Length of message.
    nlMsg->nlmsg_type = RTM_GETROUTE;                      // Get the routes from kernel routing table .
    nlMsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;       // The message is a request for dump.
    nlMsg->nlmsg_seq = msgSeq++;                           // Sequence of the message packet.
    nlMsg->nlmsg_pid = getpid();                           // PID of process sending the request.
    // send msg
    ret = send(sock, nlMsg, nlMsg->nlmsg_len, 0);
    if (ret < 0) GOTO_ERROR(err, "send netlink socket failed, %s.", strerror(errno));
    // read netlink msg
    len = ReadNetLinkMsg(sock, msgBuf, msgSeq, getpid());
    if (len < 0) GOTO_ERROR(err, "read netlink message failed.");
    //parse netlink msg
    for (; NLMSG_OK(nlMsg, len); nlMsg = NLMSG_NEXT(nlMsg, len))
    {
        //init
        memset(&rtInfo, 0, sizeof(ROUTE_INFO));
        //parse route message
        ret = ParseRoutes(nlMsg, &rtInfo);
        if(ret != 0) continue;
        pstRtInfo  = (ROUTE_INFO *)data->data;
        pstRtInfo += data->length++;
        //memcpy
        memcpy(pstRtInfo, &rtInfo, sizeof(ROUTE_INFO));
        if(data->length >= data->cap) break;
    }

    close(sock);
    return 0;

err:
    if (sock > 0) close(sock);
    return -1;
}

int get_sub_process(int pid, char *pcBasePath, int spid[], int *num)
{
    int fd = 0, ret;
    char *str;
    char path[128] = {0};
    char buff[1024] = {0};
    if (pid <= 0) return -1;
    //process children path
    sprintf(path, "%s/proc/%d/task/%d/children", pcBasePath, pid, pid);
    //open path
    fd = open(path, O_RDONLY);
    if(fd <= 0) GOTO_ERROR(err, "open %s failed, %s.", path, strerror(errno));
    //read uptime
    ret = read(fd, buff, sizeof(buff));
    if(ret < 0) GOTO_ERROR(err, "read data from %s failed, %s.", path, strerror(errno));
    //close
    close(fd);
    //parse sub pid
    *num = 0;
    str = strtok(buff, " ");
    while (str)
    {
        spid[*num] = atoi(str);
        *num += 1;
        str = strtok(NULL, " ");
        if(!str) break;
    }
    
    return 0;
err:
    if(fd > 0) close(fd);
    return -1;
}

int get_process_starttime(int pid, char *pcBasePath, char *dst)
{
    int fd = 0, ret, i = 0;
    char *p, *str;
    char value[32] = {0};
    char path[128] = {0};
    char buff[512] = {0};
    struct tm *ftime;
    time_t boottime;
    struct timeval tv;
    //check arguments
    if ((pid <= 0) || !dst) return -1;
    //uptime path
    sprintf(path, "%s/proc/uptime", pcBasePath);
    fd = open(path, O_RDONLY);
    if(fd <= 0) GOTO_ERROR(err, "open %s failed, %s.", path, strerror(errno));
    //read uptime
    ret = read(fd, buff, sizeof(buff));
    if(ret <= 0) GOTO_ERROR(err, "read data from %s failed, %s.", path, strerror(errno));
    //get time
    gettimeofday(&tv, 0);
    boottime = tv.tv_sec - strtoul(buff, &p, 10);
    close(fd);
    //memory init
    bzero(path, sizeof(path));
    bzero(buff, sizeof(bzero));
    //stat path
    sprintf(path, "%s/proc/%d/stat", pcBasePath, pid);
    //open process stat file
    fd = open(path, O_RDONLY);
    if(fd <= 0) GOTO_ERROR(err, "open %s failed, %s.", path, strerror(errno));
    //read file
    ret = read(fd, buff, sizeof(buff));
    if(ret <= 0) GOTO_ERROR(err, "read data from %s failed, %s.", path, strerror(errno));
    //
    str = buff;
    //parse string
    while(++i)
    {
        str = strchr(str + 1, ' ');
        if(i < 21) continue;
        p = strchr(str + 1, ' ');
        memcpy(value, str + 1, p - str - 1);
        break;
    }
    //
    boottime += atol(value) / 100;
    //time format
    ftime = localtime(&boottime);
    sprintf(dst, "%04d-%02d-%02d %02d:%02d:%02d", ftime->tm_year + 1900, ftime->tm_mon + 1, ftime->tm_mday, ftime->tm_hour, ftime->tm_min, ftime->tm_sec);
    //close
    close(fd);
    return 0;
err:
    if(fd > 0) close(fd);
    return -1;
}

int get_process_user(int pid, char *pcBasePath, char *dst)
{
    uid_t uid;
    int fd = 0, ret;
    struct passwd *user = NULL;
    char *pcUidStr = NULL;
    char buff[512] = {0};
    char path[128] = {0};
    //check arguments
    if ((pid <= 0) || !dst) return -1;
    //path
    sprintf(path, "%s/proc/%d/status", pcBasePath, pid);
    //open process status file
    fd = open(path, O_RDONLY);
    if(fd <= 0) GOTO_ERROR(err, "open %s failed, %s.", path, strerror(errno));
    //read file
    ret = read(fd, buff, sizeof(buff));
    if(ret <= 0) GOTO_ERROR(err, "read data from %s failed, %s.", path, strerror(errno));
    //get uid string
    pcUidStr = strstr(buff, "Uid") + 5;
    //get uid
    uid = (uid_t)strtol(pcUidStr, NULL, 10);
    //get user
    user = getpwuid(uid);
    if(!user) {
        //GOTO_ERROR(err, "get user by uid failed, %s.", strerror(errno));
        memcpy(dst, &uid, sizeof(uid));
    } else {
        memcpy(dst, user->pw_name, strlen(user->pw_name));
    }
    //close
    close(fd);
    return 0;
err:
    if(fd > 0) close(fd);
    return -1;
}

// 根据网卡名称获取本机mac地址
static int get_local_mac(const char *if_name, char *local_mac)
{
    int sock = 0;
    struct ifreq ifr;
    //check argument
    if(!if_name || (strlen(if_name) == 0)) return -1;
    //
    bzero(&ifr, sizeof(struct ifreq));
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) GOTO_ERROR(err, "create socket error, %s.", strerror(errno));
    //if name
    strncpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name) - 1);
    //
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) GOTO_ERROR(err, "ioctl error, %s.", strerror(errno));
    //format mac
    snprintf(local_mac, MAC_ADDRSTRLEN, "%02x:%02x:%02x:%02x:%02x:%02x",
             (unsigned char)ifr.ifr_hwaddr.sa_data[0],
             (unsigned char)ifr.ifr_hwaddr.sa_data[1],
             (unsigned char)ifr.ifr_hwaddr.sa_data[2],
             (unsigned char)ifr.ifr_hwaddr.sa_data[3],
             (unsigned char)ifr.ifr_hwaddr.sa_data[4],
             (unsigned char)ifr.ifr_hwaddr.sa_data[5]);

    close(sock);
    return 0;
err:
    if (sock > 0) close(sock);
    return -1;
}

// 根据网卡名称获取本机IP地址
static int get_local_ip(const char *if_name, char *local_ip)
{
    int sock = 0;
    struct sockaddr_in sin;
    struct ifreq ifr;
    //check argument
    if(!if_name || (strlen(if_name) == 0)) return -1;
    //
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock <= 0) RETURN_ERROR(-1, "create socket error, %s.", strerror(errno));

    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));

    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) GOTO_ERROR(err, "ioctl error, %s, ifname : %s.", strerror(errno), if_name);

    memcpy(&sin, &ifr.ifr_addr, sizeof(sin));
    snprintf(local_ip, INET_ADDRSTRLEN, "%s", inet_ntoa(sin.sin_addr));

    close(sock);
    return 0;

err:
    if(sock > 0) close(sock);
    return -1;
}

// 读取配置文件获取网卡名称
int get_dev_name(DATA_HEAD *data, char *pcBasePath)
{
    FILE *fp = NULL;
    int ret, arrlen, lineNum = 0, memlen;
    IF_INFO *pstDev;
    char *dstip, ifname[64];
    char path[128] = {0};
    char buff[1024] = {0}, tmp[1024];
    struct in_addr in;
    //check argument
    if(!data || !pcBasePath) return -1;
    //data init
    data->length = 0;
    data->cap    = 8;
    //array len
    arrlen     = data->cap * sizeof(IF_INFO);
    data->data = (void *)malloc(arrlen);
    if(!data->data) RETURN_ERROR(1, "malloc memory failed, %s.", strerror(errno));
    memset(data->data, 0, sizeof(arrlen));
    //process children path
    sprintf(path, "%s/proc/net/dev", pcBasePath);
    //open path
    fp = fopen(path, "r");
    if(!fp) RETURN_ERROR(-1,  "open tcp file %s failed, %s.", path, strerror(errno));
    //read lines
    while (!feof(fp))
    {
        memset(buff, 0, sizeof(buff));
        fgets(buff, sizeof(buff) - 1, fp);
        if((lineNum++) < 2) continue;
        //init
        memset(ifname, 0, sizeof(ifname));
        //LOG_PRINT("%s", buf);
        //format data
        ret = sscanf(buff, "%[^:]", ifname);
        if(ret != 1) RETURN_ERROR(-1, "format data failed, %s, err : %s.", buff, strerror(errno));
        //delete space
        DeleteSpace(ifname);
        //filter
        if((strcmp(ifname, "lo") == 0) || (strcmp(ifname, "tunl0") == 0)) continue;
        //check data
        if(data->length >= data->cap) BREAK_ERROR("get listen port is full.");
        //save data
        pstDev  = (IF_INFO *)data->data;
        pstDev += data->length++;
        //init
        memset(pstDev, 0, sizeof(IF_INFO));
        //if name
        memcpy(pstDev->ifName, ifname, strlen(ifname));
        get_local_ip(ifname, pstDev->ipv4);
        get_local_mac(ifname, pstDev->mac);
        //
        if(data->length >= data->cap)
        {
            data->cap += 8;
            memlen     = data->cap * sizeof(IF_INFO);
            pstDev      = (IF_INFO *)malloc(memlen);
            memset(pstDev, 0, memlen);
            memcpy(pstDev, data->data, arrlen);
            arrlen = memlen;
            free(data->data);
            data->data = (void *)pstDev;
        }
    }
    fclose(fp);
    //check result
    if(data->length == 0) RETURN_ERROR(-1, "get dev name failed.");
    return 0;
err:
    if(fp) fclose(fp);
    return -1;
}

// 读取配置文件获取网卡名称
int get_if_info(DATA_HEAD *data)
{
    int arrlen = 0, memlen = 0;
    struct ifaddrs *ifap, *ifa;
    struct sockaddr_in6 *sa;
    struct sockaddr_in *sa4;
    IF_INFO *pstIf = NULL;
    char addr6[INET6_ADDRSTRLEN];
    char ipv6[INET6_ADDRSTRLEN];
    //data init
    data->length = 0;
    data->cap    = 8;
    //array len
    arrlen     = data->cap * sizeof(IF_INFO);
    data->data = (void *)malloc(arrlen);
    if(!data->data) RETURN_ERROR(-1, "malloc memory failed, %s.", strerror(errno));
    //memory init
    memset(data->data, 0, sizeof(arrlen));
    //get if
    getifaddrs(&ifap);
    for (ifa = ifap; ifa; ifa = ifa->ifa_next)
    {
        memset(addr6, 0, sizeof(addr6));
        memset(ipv6, 0, sizeof(ipv6));
        //filter lo
        if(strcmp(ifa->ifa_name, "lo") == 0) continue;
        //ipv6
        if (ifa->ifa_addr->sa_family == AF_INET6)
        {
            pstIf  = (IF_INFO *)data->data;
            pstIf += data->length++;
            sa = (struct sockaddr_in6 *)ifa->ifa_addr;
            getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in6), addr6, sizeof(addr6), NULL, 0, NI_NUMERICHOST);
            // ipv6
            inet_ntop(AF_INET6, &sa->sin6_addr, ipv6, sizeof(ipv6));
            // get mac
            get_local_ip(ifa->ifa_name, pstIf->ipv4);
            get_local_mac(ifa->ifa_name, pstIf->mac);
            memcpy(pstIf->ipv6, ipv6, sizeof(ipv6));
            memcpy(pstIf->ifName, ifa->ifa_name, strlen(ifa->ifa_name));
            //
            if(data->length >= data->cap)
            {
                data->cap += 8;
                memlen     = data->cap * sizeof(IF_INFO);
                pstIf      = (IF_INFO *)malloc(memlen);
                memset(pstIf, 0, memlen);
                memcpy(pstIf, data->data, arrlen);
                arrlen = memlen;
                free(data->data);
                data->data = (void *)pstIf;
            }
        }
    }

    freeifaddrs(ifap);
    return 0;
}

int get_listen_port(DATA_HEAD *data, char *pcBasePath)
{
    FILE *fp;
    char buf[1024], netdata[6][33];
    char files[4][64] = {{"/proc/net/tcp"}, {"/proc/net/tcp6"}, {"/proc/net/udp"}, {"/proc/net/udp6"}};
    int arrlen, localPort, remotePort, state, i, lineNum, ret, proto, memlen = 0;
    LISTEN_PORT *lport;
    //check argument
    if(!data) return -2;
    //data init
    data->length = 0;
    data->cap    = 16;
    //array len
    arrlen     = data->cap * sizeof(LISTEN_PORT);
    data->data = (void *)malloc(arrlen);
    if(!data->data) RETURN_ERROR(-1, "malloc memory failed, %s.", strerror(errno));
    //memory init
    memset(data->data, 0, sizeof(arrlen));
    //get process information
    for(i = 0; i < 4; i++)
    {
        fp = fopen(files[i], "r");
        if(!fp) CONTINUE_ERROR("open tcp file %s failed, %s.", files[i], strerror(errno));

        lineNum = 0;
        proto   = (i < 2) ? IPPROTO_TCP : IPPROTO_UDP;
        //read lines
        while (!feof(fp))
        {
            memset(buf, 0, sizeof(buf));
            fgets(buf, sizeof(buf) - 1, fp);
            if(((lineNum++) == 0) || (strlen(buf) < 64)) continue;
            //LOG_PRINT("%s", buf);
            ret = ParseNetRawData(buf, netdata);
            if(ret != 0) continue;
            //state
            state = HexToDec(netdata[4]);
            //tcp
            if((proto == IPPROTO_TCP) && (state != LINK_ST_LISTEN)) break;
            //get port
            localPort  = HexToDec(netdata[1]);
            remotePort = HexToDec(netdata[3]);
            //check remote port
            if(remotePort != 0) break;
            //save data
            lport  = (LISTEN_PORT *)data->data;
            lport += data->length++;
            lport->port  = localPort;
            lport->proto = proto;
            //
            if(data->length >= data->cap)
            {
                data->cap += 8;
                memlen     = data->cap * sizeof(LISTEN_PORT);
                lport      = (LISTEN_PORT *)malloc(memlen);
                memset(lport, 0, memlen);
                memcpy(lport, data->data, arrlen);
                arrlen = memlen;
                free(data->data);
                data->data = (void *)lport;
            }
        }
        fclose(fp);
    }
    //return
    return (data->length > 0) ? 0 : -1;
}

/*
int main(int argc, char *argv[])
{
    DATA_HEAD   data;
    IF_INFO     *pstIf = NULL;
    ROUTE_INFO  *pstRtInfo;
    LISTEN_PORT *pstLport;
    DEFAULT_ROUTE *pstDefRoute;
    struct in_addr gate;
    int i, ret, pid = 0, num = 0, cpids[10];
    char value[64] = {0};
    if(argc > 1) pid = atoi(argv[1]);
    //
    if(pid > 0)
    {
        ret = get_process_starttime(pid, "", value);
        if(ret != 0) LOG_ERROR("get process start time failed.");
        LOG_PRINT("process time : %s.", value);
        //
        bzero(value, sizeof(value));
        ret = get_process_user(pid, "", value);
        if(ret != 0) LOG_ERROR("get process user failed.");
        LOG_PRINT("process user : %s.", value);
        //
        ret = get_sub_process(pid, "", cpids, &num);
        if(ret != 0) LOG_ERROR("get process user failed.");
        //list children
        for(ret = 0; ret < num; ret++)
        {
            LOG_PRINT("children pid : %d.", cpids[ret]);
        }
    }
    //
    ret = get_if_info(&data);
    if(ret != 0) LOG_ERROR("get if name failed.");
    //print
    for(i = 0; i < data.length; i++)
    {
        pstIf = (IF_INFO *)data.data;
        pstIf += i;
        LOG_PRINT("if : %s, ipv4 : %s, ipv6 : %s, mac : %s.", pstIf->ifName, pstIf->ipv4, pstIf->ipv6, pstIf->mac);
    }
    free(data.data);
    //
    ret = get_gateway(&data);
    if(ret != 0) LOG_ERROR("get gateway infor failed.");
    for(i = 0; i < data.length; i++)
    {
        pstRtInfo = (ROUTE_INFO *)data.data;
        pstRtInfo += i;
        gate.s_addr = pstRtInfo->gateWay;
        LOG_PRINT("gateway : %s, ifname : %s.", inet_ntoa(gate), pstRtInfo->ifName);
    }
    free(data.data);
    //get listen port
    ret = get_listen_port(&data, "");
    if(ret != 0) LOG_ERROR("get listen port infor failed.");
    for(i = 0; i < data.length; i++)
    {
        pstLport  = (LISTEN_PORT *)data.data;
        pstLport += i;
        LOG_PRINT("listen port : %d, proto : %s.", pstLport->port, (pstLport->proto == IPPROTO_TCP) ? "tcp" : "udp");
    }
    free(data.data);
    //get default gateway
    ret = get_default_gateway(&data, "");
    if(ret != 0) LOG_ERROR("get default gateway infor failed.");
    for(i = 0; i < data.length; i++)
    {
        pstDefRoute = (DEFAULT_ROUTE *)data.data;
        pstDefRoute += i;
        LOG_PRINT("default gateway : %s, ifname : %s.", pstDefRoute->gateway, pstDefRoute->ifName);
    }
    free(data.data);

    //get default gateway
    ret = get_dev_name(&data, "");
    if(ret != 0) LOG_ERROR("get dev name infor failed.");
    for(i = 0; i < data.length; i++)
    {
        pstIf = (IF_INFO *)data.data;
        pstIf += i;
        LOG_PRINT("if : %s, ipv4 : %s, ipv6 : %s, mac : %s.", pstIf->ifName, pstIf->ipv4, pstIf->ipv6, pstIf->mac);
    }
    free(data.data);
    
    return 0;
}
*/