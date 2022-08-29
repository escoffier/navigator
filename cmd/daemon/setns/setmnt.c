#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h> 
#include <sys/stat.h> 
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <unistd.h>

#include "cjson.h"
#include "netebpf_user.h"


static int szLocalMntNsFd = 0;

typedef struct
{
    int pid;
    int status;
    char procname[128];
} ProcessData;

char *PrintPids(int pids[], int pidsNum)
{
    int i;
    static char str[1024];
    if(pidsNum <= 0) return "";
    memset(str, 0, sizeof(str));
    for(i = 0; i < pidsNum; i++)
    {
        sprintf(str + strlen(str), "%d ", pids[i]);
    }
    return str;
}

char *PrintAddress(PidAssMnt *mnt)
{
    static char str[256];
    if(mnt == NULL) return "";
    memset(str, 0, sizeof(str));
    sprintf(str, "src pid : %d, type : %d, proto : %d, src_ip : %s, src_port : %d, dst_ip : %s, dst_port : %d",
            mnt->pid, mnt->addrType, mnt->proto, mnt->srcIp, mnt->srcPort, mnt->dstIp, mnt->dstPort);
    return str;
}

int ParseRcvJson(char *buf, PidAssMnt *mnt)
{
    cJSON *root, *item, *tuple;
    if((buf == NULL) || (mnt == NULL)) return -1;
    //set memory 0
    memset(mnt, 0, sizeof(PidAssMnt));
    //parse json
    root = cJSON_Parse(buf);
    if(root == NULL)
    {
        LOG_ERROR("parse json failed! original data : %s.", buf);
        goto err;
    }
    //get data type
    item = cJSON_GetObjectItem(root, "data_type");
    if(item == NULL)
    {
        LOG_ERROR("get data type item failed!");
        goto err;
    }
    mnt->dataType = item->valueint;
    //judge data type
    if((mnt->dataType == DATA_FILTER) || (mnt->dataType == DATA_EBPF_STATE) || (mnt->dataType == DATA_EBPF)) goto end;
    //get pid
    item = cJSON_GetObjectItem(root, "pid");
    if(item == NULL)
    {
        LOG_ERROR("get pid item failed!");
        goto err;
    }
    mnt->pid = item->valueint;
    //get addr_type
    item = cJSON_GetObjectItem(root, "addr_type");
    if(item == NULL)
    {
        LOG_ERROR("get addr_type item failed!");
        goto err;
    }
    mnt->addrType = item->valueint;
    //get tuple_info
    item = cJSON_GetObjectItem(root, "tuple_info");
    if(item == NULL)
    {
        LOG_ERROR("get tuple_info item failed!");
        goto err;
    }
    //get src_ip
    tuple = cJSON_GetObjectItem(item, "src_ip");
    if(item == NULL)
    {
        LOG_ERROR("get src_ip item failed!");
        goto err;
    }
    memcpy(mnt->srcIp, tuple->valuestring, strlen(tuple->valuestring));
    //get dst_ip
    tuple = cJSON_GetObjectItem(item, "dst_ip");
    if(item == NULL)
    {
        LOG_ERROR("get dst_ip item failed!");
        goto err;
    }
    memcpy(mnt->dstIp, tuple->valuestring, strlen(tuple->valuestring));
    //get src_port
    tuple = cJSON_GetObjectItem(item, "src_port");
    if(item == NULL)
    {
        LOG_ERROR("get src_port item failed!");
        goto err;
    }
    mnt->srcPort = tuple->valueint;
    //get dst_port
    tuple = cJSON_GetObjectItem(item, "dst_port");
    if(item == NULL)
    {
        LOG_ERROR("get dst_port item failed!");
        goto err;
    }
    mnt->dstPort = tuple->valueint;
    //get proto
    tuple = cJSON_GetObjectItem(item, "proto");
    if(item == NULL)
    {
        LOG_ERROR("get proto item failed!");
        goto err;
    }
    mnt->proto = tuple->valueint;

end:
    //free resource
    cJSON_Delete(root);
    return 0;

err:
    if(root != NULL) cJSON_Delete(root);
    return -1;
}

int GetProcessName(int pid, char *basepath, char procname[128])
{
    int fd, ret;
    char path[36];
    if((pid == 0) || (!procname)) return -2;
    memset(path, 0, sizeof(path));
    sprintf(path, "%s/proc/%d/comm", basepath, pid);
    fd = open(path, O_RDONLY);
    if(fd <= 0)
    {
        LOG_ERROR("open %s failed, %s.", path, strerror(errno));
        return -1;
    }
    //default process name length is 128 byte
    memset(procname, 0, 128);
    ret = read(fd, procname, 128);
    //close fd
    close(fd);
    if(ret <= 0)
    {
        LOG_ERROR("read process name failed, %s.", strerror(errno));
        return -1;
    }

    procname[ret - 1] = 0;
    return 0;
}

int ResultPack(PidAssMnt *mnt, ProcessData *pstProcData, char *dstBuf)
{
    int ret;
    char *str = NULL;
    cJSON *root = NULL;
    if((!mnt) || (!pstProcData) || (!dstBuf))  return -1;
    //create json object
    root = cJSON_CreateObject();
    if(root == NULL)
    {
        LOG_ERROR("create json new object failed!");
        return -1;
    }
    cJSON_AddNumberToObject(root, "pid", pstProcData->pid);
    cJSON_AddNumberToObject(root, "status", pstProcData->status);
    cJSON_AddStringToObject(root, "proc_name", pstProcData->procname);
    str = cJSON_PrintUnformatted(root);
    if(str == NULL)
    {
        LOG_ERROR("print json unformatted failed!");
        goto err;
    }
    memcpy(dstBuf, str, strlen(str));
    cJSON_Delete(root);
    free(str);
    return 0;
err:
    if(root != NULL) cJSON_Delete(root);
    if(str != NULL) free(str);
    return -1;
}

int OpenLocalMntNs()
{
    int ret;
    char path[] = "/proc/1/ns/mnt";
    ret = unshare(CLONE_NEWNS);
    if(ret != 0)
    {
        LOG_ERROR("unshare mnt failed!");
        return -1;
    }
    //open mnt namespaces
    szLocalMntNsFd = open(path, O_RDONLY);
    if(szLocalMntNsFd <= 0)
    {
        LOG_ERROR("open %s mnt namespaces failed!", path);
        return -1;
    }
    return 0;
}

int SetLocalMntNs()
{
    int ret;
    if(szLocalMntNsFd <= 0)
    {
        LOG_ERROR("local mnt ns fd is error!!");
        return -1;
    }
    //set local mnt ns
    ret = setns(szLocalMntNsFd, 0);
    if(ret != 0)
    {
        LOG_ERROR("set local mnt ns failed!");
        return -1;
    }
    return 0;
}

int SetNs(int pid)
{
    int fd, ret;
    char path[128];
    if(pid <= 0)
    {
        LOG_ERROR("pid is error!");
        return -1;
    }
    memset(path, 0, sizeof(path));
    sprintf(path, "%s/proc/%d/ns/mnt", BasePath, pid);
    fd = open(path, O_RDONLY);
    if(fd <= 0)
    {
        LOG_ERROR("open %s failed!", path);
        return -1;
    }
    //set mnt ns
    ret = setns(fd, 0);
    //close fd
    close(fd);
    if(ret != 0)
    {
        LOG_ERROR("set mnt ns failed, %s!", path);
        return -1;
    }
    return 0;
}

int ReadAllPid(char *path, int *procNum, int pids[])
{
    int i = 0;
    DIR *pDir; 
    struct dirent *ent;
    
    if((path == NULL) || (procNum == NULL) || (*procNum <= 0))
    {
        LOG_ERROR("read pid failed with use error argument!");
        return -1;
    }
    pDir = opendir(path);
    if(pDir == NULL)
    {
        LOG_ERROR("open dir : %s failed!", path);
        return -1;
    }

    while ((ent = readdir(pDir)) != NULL)
    {
        if(!(ent->d_type & DT_DIR)) continue;
        if(ent->d_name[0] < 48 || ent->d_name[0] > 57) continue;
        if((strspn(ent->d_name, "0123456789") != strlen(ent->d_name))) continue;
        if(i >= *procNum) break;
        pids[i++] = atoi(ent->d_name);
    }
    //close
    closedir(pDir);
    //
    if(i == 0)
    {
        LOG_ERROR("get pid failed! path : %s.", path);
        return -1;
    }
    //
    *procNum = i;
    return 0;
}

int GetProcNetFiles(int proto, int *filesNum, int pids[], char filesPath[][128])
{
    int i, j = 0;

    if(!filesNum) return -2;

    for(i = 0; i < *filesNum; i++)
    {
        if(pids[i] <= 0) continue;

        switch(proto)
        {
            case IPPROTO_TCP:
                memset(filesPath[j], 0, sizeof(filesPath[j]));
                sprintf(filesPath[j++], "/proc/%d/net/tcp", pids[i]);
                memset(filesPath[j], 0, sizeof(filesPath[j]));
                sprintf(filesPath[j++], "/proc/%d/net/tcp6", pids[i]);
                break;
            case IPPROTO_UDP:
                memset(filesPath[j], 0, sizeof(filesPath[j]));
                sprintf(filesPath[j++], "/proc/%d/net/udp", pids[i]);
                memset(filesPath[j], 0, sizeof(filesPath[j]));
                sprintf(filesPath[j++], "/proc/%d/net/udp6", pids[i]);
                break;
            default:
                break;
        }
    }

    if(j == 0)
    {
        LOG_ERROR("get all pid's net file failed!");
        return -1;
    }
    //
    *filesNum = j;
    return 0;
}

int HexToDec(char *data)
{
    if(data == NULL) return 0;
    return strtol(data, NULL, 16);
}

void FormatIpString(char *buf, char ip[16][3])
{
    int i = 0;
    for(i = 0; i < strlen(buf) / 2; i++)
    {
        memset(ip[i], 0, sizeof(ip[i]));
        memcpy(ip[i], buf + (i * 2), 2);
    }
}

char *ConvertIp(char *buf)
{
    int len;
    char str[16][3];
    static int seq = 0;
    static char ip[10][32];
    if(buf == NULL) return "";
    memset(ip[seq % 10], 0, sizeof(ip[seq % 10]));
    len = strlen(buf);
    if(len <= 8)
    {
        FormatIpString(buf, str);
        sprintf(ip[seq % 10], "%d.%d.%d.%d", HexToDec(str[3]), HexToDec(str[2]), HexToDec(str[1]), HexToDec(str[0]));
    }
    else
    {
        FormatIpString(buf, str);
        sprintf(ip[seq % 10], "%s%s:%s%s:%s%s:%s%s:%s%s:%s%s:%s%s:%s%s",
        str[14], str[15], str[13], str[12], str[10], str[11], str[8], str[9],
        str[6], str[7], str[4], str[5], str[2], str[3], str[0], str[1]);
    }
    return ip[(seq++) % 10];
}

int ParseNetRawData(char *data, char netdata[6][33])
{
    int ret, i = 0, index = 0;
    char *str, *p, tmp[1024] = {0};
    if(data == NULL) return -2;
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

    if(index != 6)
    {
        LOG_ERROR("format net raw data failed! %s.", tmp);
        return -1;
    }

    return 0;
}

int MatchInode(char *inode, int pidNums, int pids[], int *pid)
{
    int ret, i, value;
    DIR *pDir;
    char path[128], link[32], dirPath[64], sinode[32];
    struct dirent *ent;
    if((!inode) || (!pid) || (pidNums == 0)) return -2;
    //socket inode
    memset(sinode, 0, sizeof(sinode));
    sprintf(sinode, "socket:[%s]", inode);
    //match inode
    for(i = 0; i < pidNums; i++)
    {
        memset(dirPath, 0, sizeof(dirPath));
        sprintf(dirPath, "/proc/%d/fd", pids[i]);
        pDir = opendir(dirPath);
        if(!pDir)
        {
            LOG_WARN("open dir : %s failed!", dirPath);
            continue;
        }
        while((ent = readdir(pDir)) != NULL)
        {
            if(ent->d_type & DT_DIR) continue;
            value = atoi(ent->d_name);
            if(value < 3) continue;
            memset(path, 0, sizeof(path));
            memset(link, 0, sizeof(link));
            sprintf(path, "%s/%d", dirPath, value);
            ret = readlink(path, link, sizeof(link));
            if(ret < 0)
            {
                LOG_WARN("readlink failed, path : %s, %s.", path, strerror(errno));
                continue;
            }
            //compare
            if(strcmp(sinode, link) == 0)
            {
                //close
                closedir(pDir);
                *pid = pids[i];
                return 0;
            }
        }
        //close
        closedir(pDir);
    }
    //set pid
    *pid = 0;
    return -1;
}

int GetProcessWithTcp(PidAssMnt *mnt, int pidNums, int pids[], int filesNum, char files[][128], ProcessData *pstProcData)
{
    FILE *fp;
    char buf[1024], netdata[6][33];
    char *localIp, *inode;
    int localPort, state, i, lineNum, pid = 0, ret = -1;
    if((!pstProcData) || (!mnt)) return -2;
    //set default value
    memset(pstProcData, 0, sizeof(ProcessData));
    //get process information
    for(i = 0; i < filesNum; i++)
    {
        fp = fopen(files[i], "r");
        if(fp == NULL)
        {
            LOG_ERROR("open tcp file %s failed, pids : %s, %s.", files[i], PrintPids(pids, pidNums), strerror(errno));
            continue;
        }
        
        lineNum = 0;
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
            if((state != LINK_ST_ESTABLISHED) && (state != LINK_ST_LISTEN)) continue;
            //match address
            localIp = ConvertIp(netdata[0]);
            localPort = HexToDec(netdata[1]);
            inode = netdata[5];
            if(mnt->addrType == RCV_ADDR)
            {
                if(localPort != mnt->dstPort) continue;
                if(state != LINK_ST_ESTABLISHED) break;
            }
            else
            {
                if((localPort != mnt->srcPort) || (strcmp(localIp, mnt->srcIp) != 0)) continue;
            }
            //set flag
            pstProcData->status = MATCH_SUCC;
            //match inode
            ret = MatchInode(inode, pidNums, pids, &pid);
            //if(ret != 0) BREAK_ERROR("match tcp inode failed! need enter other container, inode : %s.", inode);
            if(ret != 0) break;
            //get process name by pid
            ret = GetProcessName(pid, "", pstProcData->procname);
            if(ret != 0) {
                LOG_ERROR("get tcp process name failed! pid : %d, %s.", pid, PrintAddress(mnt));
            } else {
                pstProcData->status = GET_DATA_SUCC;
            }
            break;
        }
        fclose(fp);
        if(pstProcData->status != 0) break;
    }
    //return
    return ret;
}

int GetProcessWithUdp(PidAssMnt *mnt, int pidNums, int pids[], int filesNum, char files[][128], ProcessData *pstProcData)
{
    FILE *fp;
    char buf[1024], netdata[6][33];
    char *localIp, *inode;
    int localPort, state, i, lineNum, pid = 0, ret = -1;
    if((!pstProcData) || (!mnt)) return -2;
    //set default value
    memset(pstProcData, 0, sizeof(ProcessData));
    //get process information
    for(i = 0; i < filesNum; i++)
    {
        fp = fopen(files[i], "r");
        if(fp == NULL)
        {
            LOG_ERROR("open udp file %s failed, pids : %s, %s.", files[i], PrintPids(pids, pidNums), strerror(errno));
            continue;
        }

        lineNum = 0;
        while (!feof(fp))
        {
            memset(buf, 0, sizeof(buf));
            fgets(buf, sizeof(buf) - 1, fp);
            if(((lineNum++) == 0) || (strlen(buf) < 64)) continue;
            //LOG_PRINT("%s", buf);
            ret = ParseNetRawData(buf, netdata);
            if(ret != 0) continue;
            //match address
            localIp = ConvertIp(netdata[0]);
            localPort = HexToDec(netdata[1]);
            inode = netdata[5];
            if(mnt->addrType == RCV_ADDR)
            {
                if((localPort != mnt->dstPort)) continue;
            }
            else
            {
                if((localPort != mnt->srcPort) || (strcmp(localIp, mnt->srcIp) != 0)) continue;
            }
            //set flag
            pstProcData->status = MATCH_SUCC;
            //match inode
            ret = MatchInode(inode, pidNums, pids, &pid);
            if(ret != 0) BREAK_ERROR("match udp inode failed! need enter other container, inode : %s.", inode);
            //get process name by pid
            ret = GetProcessName(pid, "", pstProcData->procname);
            if(ret != 0) {
                LOG_ERROR("get udp process name failed! pid : %d, %s.", pid, PrintAddress(mnt));
            } else {
                pstProcData->status = GET_DATA_SUCC;
            }
            break;
        }
        fclose(fp);
        if(pstProcData->status != 0) break;
    }

    //return
    return ret;
}

int GetProcessData(PidAssMnt *mnt, ProcessData *pstProcData)
{
    int pidNums = 30, filesNum = 2;
    int ret, pids[30], pid;
    char files[20][128];
    const char *pcDefPath = NULL;
    if((!mnt) || (!pstProcData)) return -2;
    if(pidNums > (sizeof(pids) / sizeof(int))) return -3;
    //set 0
    memset(pids, 0, sizeof(pids));
    //get pid
    ret = ReadAllPid("/proc", &pidNums, pids);
    if(ret != 0) return ret;
    //get net files
    ret = GetProcNetFiles(mnt->proto, &filesNum, pids, files);
    if(ret != 0) return ret;
    //
    switch (mnt->proto)
    {
        case IPPROTO_TCP:
            ret = GetProcessWithTcp(mnt, pidNums, pids, filesNum, files, pstProcData);
            break;
        case IPPROTO_UDP:
            ret = GetProcessWithUdp(mnt, pidNums, pids, filesNum, files, pstProcData);
            break;
        default:
            LOG_ERROR("proto is error, proto : %d.", mnt->proto);
            return -4;
    }
    //status
    switch(pstProcData->status)
    {
        case 0:
            //unshare mnt
            unshare(CLONE_NEWNS);
            //set local mnt
            SetLocalMntNs();
            //set default pid
            pid = mnt->pid;
            pcDefPath = BasePath;
            break;
        case GET_DATA_SUCC:
            return 0;
        case MATCH_SUCC:
            pid = pids[0];
            pcDefPath = "";
            break;
        default:
            LOG_ERROR("get process status is error! pid : %d, %s.", pstProcData->pid, PrintAddress(mnt));
            break;
    }
    //set default
    pstProcData->pid =pid;
    //get process name by pid
    ret = GetProcessName(pid, pcDefPath, pstProcData->procname);
    if(ret != 0) LOG_ERROR("get tcp process name failed by default pid! pid : %d, %s.", pid, PrintAddress(mnt));
    //print information

    return ret;
}

int ParseRcvData(int fd, char *buf)
{
    int ret, length;
    char result[256], *retdata = NULL, *str = NULL;
    PidAssMnt mnt;
    ProcessData stProcData;
    if((fd <= 0) || (!buf))
    {
        LOG_ERROR("parse failed by argumnet is error!");
        return -2;
    }
    //set 0
    memset(result, 0, sizeof(result));
    memset(&stProcData, 0, sizeof(stProcData));
    //parse json
    ret = ParseRcvJson(buf, &mnt);
    if(ret < 0)
    {
        LOG_ERROR("parse receive json failed!");
        goto out;
    }
    //init buf
    memset(result, 0, sizeof(result));
    //condition
    switch (mnt.dataType)
    {
        case DATA_EBPF_STATE:
            //parse json
            ret = parse_get_ebpf_state(buf, result, sizeof(result));
            if(ret != 0) LOG_ERROR("parse get ebpf state failed.");
            //move point
            retdata = result;
            goto rsp;

        case DATA_FILTER:
            return parse_filter_condition(buf);

        case DATA_EBPF:
            //set default response data
            memcpy(result, "[]", sizeof(result));
            //init response data
            retdata = result;
            //get ebpf map data
            str = lookup_ebpf_map();
            if(str) retdata = str;
            goto rsp;

        default:
            //set ns
            ret = SetNs(mnt.pid);
            if(ret < 0) goto out;
            //get process data
            ret = GetProcessData(&mnt, &stProcData);
            //if(ret != 0) LOG_ERROR("get process failed! ret : %d, %s.", ret,  PrintAddress(&mnt));
            break;
    }
   
out:
    //unshare mnt
    unshare(CLONE_NEWNS);
    //set local mnt
    SetLocalMntNs();
    //pack data
    ret = ResultPack(&mnt, &stProcData, result);
    if(ret < 0) return 0;
    retdata = result;
rsp:
    //data len
    length = strlen(retdata);
    //send response data
    ret = write(fd, retdata, length);
    //free
    if(str) free(str);
    //judge response result
    if(ret != length)
    {
        LOG_ERROR("send result failed! %s.", strerror(errno));
        if(ret <= 0) close(fd);
        return 0;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    char buf[1024];
    socklen_t cliAddrLen;
    struct sockaddr_un svrAddr, cltAddr;
    struct epoll_event ev, events[20];
    int zListenFd = 0, epfd = 0, zClientFd, zLinkFd;
    int ret, zDataLen, nfds, i;
    //open local mnt namespaces
    OpenLocalMntNs();
    //epoll fd
    epfd = epoll_create(256);
    if(epfd <= 0)
    {
        LOG_ERROR("create epoll fd failed, %s.", strerror(errno));
        goto err;
    }
    zListenFd = socket(PF_UNIX, SOCK_STREAM, 0);
    if(zListenFd <= 0)
    {
        LOG_ERROR("create unix socket failed! %s.", strerror(errno));
        goto err;
    }
    svrAddr.sun_family = AF_UNIX;
    strcpy(svrAddr.sun_path, DAEMON_UNIX);
    unlink(DAEMON_UNIX);
    //bind socket address
    ret = bind(zListenFd, (struct sockaddr *)&svrAddr, sizeof(svrAddr));
    if(ret < 0)
    {
        LOG_ERROR("bind server unix socket failed, %s!", strerror(errno));
        goto err;
    }
    //listen sockfd
    ret = listen(zListenFd, 1);
    if(ret < 0)
    {
        LOG_ERROR("listen the client connect request!");
        goto err;
    }
    //register epoll event
    ev.data.fd = zListenFd;
    ev.events = EPOLLIN;
    ret = epoll_ctl(epfd, EPOLL_CTL_ADD, zListenFd, &ev);
    if(ret < 0)
    {
        LOG_ERROR("epoll ctl failed, %s.", strerror(errno));
        goto err;
    }
    //accept client request
    while (1)
    {
        nfds = epoll_wait(epfd, events, 20, -1);
        for(i = 0; i < nfds; i++)
        {
            zLinkFd = events[i].data.fd;
            if(zLinkFd <= 0) continue;
            //new connect event
            if(zLinkFd == zListenFd)
            {
                //client address length
                cliAddrLen = sizeof(struct sockaddr_in);
                zClientFd = accept(zListenFd, (struct sockaddr *)&cltAddr, &cliAddrLen);
                if(zClientFd <= 0)
                {
                    LOG_ERROR("accept a new client failed, %s.", strerror(errno));
                    continue;
                }
                ev.data.fd = zClientFd;
                ev.events = EPOLLIN;
                ret = epoll_ctl(epfd, EPOLL_CTL_ADD, zClientFd, &ev);
                if(ret < 0)
                {
                    close(zClientFd);
                    LOG_ERROR("add new client to epoll failed, %s.", strerror(errno));
                }
                continue;
            }
            //handle event
            if(events[i].events & EPOLLIN)
            {
                memset(buf, 0, sizeof(buf));
                ret = read(zLinkFd, buf, sizeof(buf));
                if(ret <= 0)
                {
                    close(zLinkFd);
                    LOG_ERROR("read data failed, close fd.");
                    continue;
                }
                //parse data
                ret = ParseRcvData(zLinkFd, buf);
                if(ret != 0)
                {
                    LOG_ERROR("parse receive data failed.");
                }
            }
        }
    }
    
err:
    if(zListenFd > 0) close(zListenFd);
    if(epfd > 0) close(epfd);
    return -1;
}
