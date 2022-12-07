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
#include <arpa/inet.h>

#include "cjson.h"
#include "netebpf_user.h"


static int szLocalMntNsFd = 0;

typedef struct
{
    int pid;
    int status;
    char procname[128];
} ProcessData;

int ReadFileList(char *path)
{
    DIR *dir;
    struct dirent *ptr;
    //open dir
    dir = opendir(path);
    if(!dir) RETURN_ERROR(-1, "open dir %s failed, err : %s.", path, strerror(errno));
    //read dir
    while ((ptr = readdir(dir)) != NULL)
    {
        if(strcmp(ptr->d_name,".") == 0 || strcmp(ptr->d_name,"..") == 0)    ///current dir OR parrent dir
            continue;
        else if(ptr->d_type == 8)    ///file
            printf("%s ", ptr->d_name);
        else if(ptr->d_type == 10)    ///link file
            printf("%s ", ptr->d_name);
        else if(ptr->d_type == 4)    ///dir
        {
            printf("%s ", ptr->d_name);
        }
    }
    closedir(dir);
    printf("\n");

    return 0;
}

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

int Ipv6Equal(char *addr1, char *addr2)
{
    int ret = -1, i = 0;
    unsigned char n_addr1[17];
    unsigned char n_addr2[17];

    if(!addr1 || !addr2) return -1;
    //init
    memset(n_addr1, 0, sizeof(n_addr1));
    memset(n_addr2, 0, sizeof(n_addr2));
    //convert
    ret = inet_pton(AF_INET6, addr1, &(n_addr1));
    if(ret <= 0) RETURN_ERROR(-1, "format ipv6 address failed, ipv6 : %s.", addr1);
    //
    ret = inet_pton(AF_INET6, addr2, &(n_addr2));
    if(ret <= 0) RETURN_ERROR(-1, "format ipv6 address failed, ipv6 : %s.", addr2);
    //
    if(memcmp(n_addr1, n_addr2, sizeof(n_addr1)) == 0 ) return 0;

    return -1;
}

int ParseRcvJson(char *buf, PidAssMnt *mnt)
{
    cJSON *root, *item, *tuple;
    if((buf == NULL) || (mnt == NULL)) return -1;
    //set memory 0
    memset(mnt, 0, sizeof(PidAssMnt));
    //parse json
    root = cJSON_Parse(buf);
    if(root == NULL) GOTO_ERROR(err, "parse json failed! original data : %s.", buf);

    //get data type
    item = cJSON_GetObjectItem(root, "data_type");
    if(item == NULL) GOTO_ERROR(err, "get data type item failed!");
    mnt->dataType = item->valueint;

    //judge data type
    if((mnt->dataType == DATA_FILTER) || (mnt->dataType == DATA_EBPF_STATE) || (mnt->dataType == DATA_EBPF) || (mnt->dataType == DATA_HOST_GATEWAY)) goto end;
    //get pid
    item = cJSON_GetObjectItem(root, "pid");
    if(item == NULL) GOTO_ERROR(err, "get pid item failed!");
    mnt->pid = item->valueint;
    if(mnt->dataType == DATA_CONTAINER) goto end;

    //get addr_type
    item = cJSON_GetObjectItem(root, "addr_type");
    if(item == NULL) GOTO_ERROR(err, "get addr_type item failed!");
    mnt->addrType = item->valueint;
    //get tuple_info
    item = cJSON_GetObjectItem(root, "tuple_info");
    if(item == NULL) GOTO_ERROR(err, "get tuple_info item failed!");

    //get src_ip
    tuple = cJSON_GetObjectItem(item, "src_ip");
    if(item == NULL) GOTO_ERROR(err, "get src_ip item failed!");
    memcpy(mnt->srcIp, tuple->valuestring, strlen(tuple->valuestring));

    //get dst_ip
    tuple = cJSON_GetObjectItem(item, "dst_ip");
    if(item == NULL) GOTO_ERROR(err, "get dst_ip item failed!");
    memcpy(mnt->dstIp, tuple->valuestring, strlen(tuple->valuestring));

    //get src_port
    tuple = cJSON_GetObjectItem(item, "src_port");
    if(item == NULL) GOTO_ERROR(err, "get src_port item failed!");
    mnt->srcPort = tuple->valueint;

    //get dst_port
    tuple = cJSON_GetObjectItem(item, "dst_port");
    if(item == NULL) GOTO_ERROR(err, "get dst_port item failed!");
    mnt->dstPort = tuple->valueint;

    //get proto
    tuple = cJSON_GetObjectItem(item, "proto");
    if(item == NULL) GOTO_ERROR(err, "get proto item failed!");
    mnt->proto = tuple->valueint;

end:
    //free resource
    cJSON_Delete(root);
    return 0;

err:
    if(root != NULL) cJSON_Delete(root);
    return -1;
}

int GetProcessName(int pid, const char *basepath, char procname[128])
{
    int fd, ret;
    char path[36];
    if((pid <= 0) || (!procname)) return -2;

    memset(path, 0, sizeof(path));
    sprintf(path, "%s/proc/%d/comm", basepath, pid);
    //open path
    fd = open(path, O_RDONLY);
    if(fd <= 0) RETURN_ERROR(-1, "open %s failed, %s.", path, strerror(errno));
    //default process name length is 128 byte
    memset(procname, 0, 128);
    ret = read(fd, procname, 128);
    //close fd
    close(fd);
    if(ret <= 0) RETURN_ERROR(-1, "read process name failed, %s.", strerror(errno));
    //string end
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
    if(!root) RETURN_ERROR(-1, "create json new object failed!");
    //set default pid
    pstProcData->pid = (pstProcData->pid > 0) ? pstProcData->pid : mnt->pid;
    //json add
    cJSON_AddNumberToObject(root, "pid", pstProcData->pid);
    cJSON_AddNumberToObject(root, "status", pstProcData->status);
    cJSON_AddStringToObject(root, "proc_name", pstProcData->procname);
    str = cJSON_PrintUnformatted(root);
    if(str == NULL) GOTO_ERROR(err, "print json unformatted failed!");
    //copy
    memcpy(dstBuf, str, strlen(str));
    cJSON_Delete(root);
    free(str);

    return 0;
err:
    if(root != NULL) cJSON_Delete(root);
    if(str != NULL) free(str);

    return -1;
}

int GetLocalMnt(char *path)
{
    DIR *pDir;
    char comm[128];
    int i = 0, pid = 0, ret;
    struct dirent *ent;
    //
    if(!path) RETURN_ERROR(-1, "read pid failed with use error argument!");
    //open dir
    pDir = opendir(path);
    if(!pDir) RETURN_ERROR(-1, "open dir : %s failed!", path);
    //read dir
    while ((ent = readdir(pDir)) != NULL)
    {
        if(!(ent->d_type & DT_DIR)) continue;
        if(ent->d_name[0] < 48 || ent->d_name[0] > 57) continue;
        if((strspn(ent->d_name, "0123456789") != strlen(ent->d_name))) continue;
        pid = atoi(ent->d_name);
        //init
        memset(comm, 0, sizeof(comm));
        ret = GetProcessName(pid, "", comm);
        if(ret != 0) CONTINUE_ERROR("get process name failed, pid : %d.", pid);
        //
        if(strcmp(comm, "supervisord") == 0)
        {
            closedir(pDir);
            return pid;
        }
    }
    //close
    closedir(pDir);
    //
    return 0;
}

int OpenLocalMntNs()
{
    int ret, pid = 0;
    char *path = "/proc/%d/ns/mnt";
    char buff[128] = {0};
    //get pid
    pid = GetLocalMnt("/proc");
    if(pid <= 0) RETURN_ERROR(-1, "get local pid failed.");
    //
    memset(buff, 0, sizeof(buff));
    sprintf(buff, path, pid);
    //open mnt namespaces
    szLocalMntNsFd = open(buff, O_RDONLY);
    if(szLocalMntNsFd <= 0) RETURN_ERROR(-1, "open %s mnt namespaces failed! err : %s.", buff, strerror(errno));

    return 0;
}

int SetLocalMntNs(int fd)
{
    int ret;
    if(fd <= 0) RETURN_ERROR(-1, "local mnt ns fd is error!!");
    //unshare mnt
    ret = unshare(CLONE_NEWNS);
    if(ret != 0) RETURN_ERROR(-1, "unshare mnt failed! err : %s.", strerror(errno));
    //set local mnt ns
    ret = setns(fd, CLONE_NEWNS);
    if(ret != 0) RETURN_ERROR(-1, "set local mnt ns failed! err : %s.", strerror(errno));

    return 0;
}

int SetNs(int pid)
{
    int fd = 0, ret;
    char path[128];
    if(pid <= 0) RETURN_ERROR(-1, "pid is error!");
    //set local mnt
    //ret = SetLocalMntNs(szLocalMntNsFd);
    //if(ret != 0) RETURN_ERROR(ret, "set local mnt ns failed!");
    //path
    memset(path, 0, sizeof(path));
    sprintf(path, "%s/proc/%d/ns/mnt", BasePath, pid);
    //open path
    fd = open(path, O_RDONLY);
    if(fd <= 0) RETURN_ERROR(-1, "open %s failed, err : %s.", path, strerror(errno));
    //unshare mnt
    ret = unshare(CLONE_NEWNS);
    if(ret != 0) GOTO_ERROR(err, "unshare mnt failed! err : %s.", strerror(errno));
    //set mnt ns
    ret = setns(fd, CLONE_NEWNS);
    if(ret != 0) GOTO_ERROR(err, "set mnt ns failed, path : %s, err : %s.", path, strerror(errno));
    //close fd
    close(fd);
    //return
    return 0;
err:
    if(fd > 0) close(fd);
    return -1;
}

int ReadAllPid(char *path, int *procNum, int pids[])
{
    int i = 0;
    DIR *pDir; 
    struct dirent *ent;
    
    if(!path || !procNum || (*procNum <= 0))  RETURN_ERROR(-1, "read pid failed with use error argument!");

    pDir = opendir(path);
    if(pDir == NULL) RETURN_ERROR(-1, "open dir : %s failed!", path);

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
    if(i == 0) RETURN_ERROR(-1, "get pid failed! path : %s.", path);
   //
    *procNum = i;
    return 0;
}

int GetProcNetFiles(int proto, int pid, char filesPath[][256])
{
    int j = 0;

    switch(proto)
    {
        case IPPROTO_TCP:
            memset(filesPath[j], 0, sizeof(filesPath[j]));
            sprintf(filesPath[j++], "/proc/%d/net/tcp", pid);
            memset(filesPath[j], 0, sizeof(filesPath[j]));
            sprintf(filesPath[j++], "/proc/%d/net/tcp6", pid);
            break;
        case IPPROTO_UDP:
            memset(filesPath[j], 0, sizeof(filesPath[j]));
            sprintf(filesPath[j++], "/proc/%d/net/udp", pid);
            memset(filesPath[j], 0, sizeof(filesPath[j]));
            sprintf(filesPath[j++], "/proc/%d/net/udp6", pid);
            break;
        default:
            break;
    }

    if(j == 0) RETURN_ERROR(-1, "get all pid's net file failed!");

    return 0;
}

char HexToByte(char s)
{
    if((s <= '9') && (s >= '0')) {
        return s - '0';
    } else if ((s >= 'a') && (s <= 'f')) {
        return s - 'a' + 10;
    } else if ((s >= 'A') && (s <= 'F')) {
        return s - 'A' + 10;
    }
    return s;
}

int HexToDec(char *data)
{
    if(!data) return 0;
    return strtol(data, NULL, 16);
}

void FormatIpv4(char *buf, char ip[16][3])
{
    int i = 0;
    for(i = 0; i < strlen(buf) / 2; i++)
    {
        memset(ip[i], 0, sizeof(ip[i]));
        memcpy(ip[i], buf + (i * 2), 2);
    }
}

void FormatIpv6(char *buf, char ip[16][3])
{
    char c, d;
    int i, j, srcIndex, targetIndex;
    for(i = 0; i < 4; i++)
    {
        for(j = 0; j < 4; j++)
        {
            srcIndex = i *4 +3 -j;
            targetIndex = i *4 + j;
            c = HexToByte(buf[srcIndex * 2]);
            d = HexToByte(buf[srcIndex * 2 + 1]);
            memset(ip[targetIndex], 0, sizeof(ip[targetIndex]));
            sprintf(ip[targetIndex], "%02x", c * 16 + d);
        }
    }
}

char *ConvertIp(char *buf)
{
    int len;
    char str[16][3];
    static int seq = 0;
    static char ip[10][INET6_ADDRSTRLEN];
    if(buf == NULL) return "";
    memset(ip[seq % 10], 0, sizeof(ip[seq % 10]));
    len = strlen(buf);
    if(len <= 8)
    {
        FormatIpv4(buf, str);
        sprintf(ip[seq % 10], "%d.%d.%d.%d", HexToDec(str[3]), HexToDec(str[2]), HexToDec(str[1]), HexToDec(str[0]));
    }
    else
    {
        FormatIpv6(buf, str);
        sprintf(ip[seq % 10], "%s%s:%s%s:%s%s:%s%s:%s%s:%s%s:%s%s:%s%s",
        str[0], str[1], str[2], str[3], str[4], str[5], str[6], str[7],
        str[8], str[9], str[10], str[11], str[12], str[13], str[14], str[15]);
        LOG_PRINT("ipv6 : %s.", ip[seq % 10]);
    }

    return ip[(seq++) % 10];
}

int IpEqual(char *buf, char *ip)
{
    int ret;
    char *localIp;
    if(!buf || !ip) return -1;
    localIp = ConvertIp(buf);
    if(strlen(buf) <= 8) return strcmp(localIp, ip);
    /*compare ipv6*/
    return Ipv6Equal(localIp, ip);
}

int ParseNetRawData(char *data, char netdata[6][48])
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
        if(!pDir) CONTINUE_ERROR("open dir : %s failed!", dirPath);

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
                if(errno == ENOENT) break;
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

int GetProcessWithTcp(PidAssMnt *mnt, int pidNums, int pids[], int filesNum, char files[][256], ProcessData *pstProcData)
{
    FILE *fp;
    char buf[1024], netdata[6][48];
    char *localIp, *inode;
    int localPort, state, i, lineNum, pid = 0, ret = -1;
    if((!pstProcData) || (!mnt)) return -2;
    //set default value
    memset(pstProcData, 0, sizeof(ProcessData));
    //print debug log
    //LOG_PRINT("proto : %d, src_ip : %s:%d, dst_ip : %s:%d.", mnt->proto, mnt->srcIp, mnt->srcPort, mnt->dstIp, mnt->dstPort);
    //get process information
    for(i = 0; i < filesNum; i++)
    {
        fp = fopen(files[i], "r");
        if(!fp) CONTINUE_ERROR("host pid : %d, open tcp file %s failed, pids : %s, %s.", mnt->pid, files[i], PrintPids(pids, pidNums), strerror(errno));
        
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
            localPort = HexToDec(netdata[1]);
            inode = netdata[5];
            if(mnt->addrType == RCV_ADDR)
            {
                if(localPort != mnt->dstPort) continue;
                if(state != LINK_ST_ESTABLISHED) break;
            }
            else
            {
                if((localPort != mnt->srcPort) || (IpEqual(netdata[0], mnt->srcIp) != 0)) continue;
            }
            //set flag
            pstProcData->status = MATCH_SUCC;
            pstProcData->pid    = pid;
            //match inode
            ret = MatchInode(inode, pidNums, pids, &pid);
            //if(ret != 0) BREAK_ERROR("match tcp inode failed! need enter other container, inode : %s.", inode);
            if(ret != 0) break;
            //get process name by pid
            ret = GetProcessName(pid, "", pstProcData->procname);
            if(ret != 0) BREAK_ERROR("get tcp process name failed! pid : %d, %s.", pid, PrintAddress(mnt));
            //set status
            pstProcData->status = GET_DATA_SUCC;
            break;
        }
        fclose(fp);
        //
        if(pstProcData->status != 0) break;
    }
    //return
    return ret;
}

int GetProcessWithUdp(PidAssMnt *mnt, int pidNums, int pids[], int filesNum, char files[][256], ProcessData *pstProcData)
{
    FILE *fp;
    char buf[1024], netdata[6][48];
    char *inode;
    int localPort, state, i, lineNum, pid = 0, ret = -1;
    if((!pstProcData) || (!mnt)) return -2;
    //set default value
    memset(pstProcData, 0, sizeof(ProcessData));
    //get process information
    for(i = 0; i < filesNum; i++)
    {
        fp = fopen(files[i], "r");
        if(!fp) CONTINUE_ERROR("open udp file %s failed, pids : %s, %s.", files[i], PrintPids(pids, pidNums), strerror(errno));

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
            localPort = HexToDec(netdata[1]);
            inode = netdata[5];
            if(mnt->addrType == RCV_ADDR)
            {
                if((localPort != mnt->dstPort)) continue;
            }
            else
            {
                if((localPort != mnt->srcPort) || (IpEqual(netdata[0], mnt->srcIp) != 0)) continue;
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

static int GetProcessData(PidAssMnt *mnt, ProcessData *pstProcData)
{
    int pidNums = 20, filesNum = 2;
    int ret, pids[30];
    char files[2][256];
    const char *pcDefPath = NULL;
    if((!mnt) || (!pstProcData)) return -2;
    if(pidNums > (sizeof(pids) / sizeof(int))) return -3;
    //set 0
    memset(pids, 0, sizeof(pids));
    //get pid
    ret = ReadAllPid("/proc", &pidNums, pids);
    if(ret != 0) return ret;
    //get net files
    ret = GetProcNetFiles(mnt->proto, pids[0], files);
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
    //set default path
    pcDefPath = "";
    //status
    switch(pstProcData->status)
    {
        case MATCH_IDLE:
        case MATCH_SUCC:
            //set local mnt
            ret = SetLocalMntNs(szLocalMntNsFd);
            if(ret != 0) RETURN_ERROR(ret, "set local mnt ns failed!");
            //set default path
            pcDefPath = BasePath;
            break;

        case GET_DATA_SUCC:
            return 0;

        default:
            LOG_ERROR("get process status is error! pid : %d, %s.", pstProcData->pid, PrintAddress(mnt));
            break;
    }
    //set pid
    pstProcData->pid = (pstProcData->pid > 0) ? pstProcData->pid : mnt->pid;
    //get process name by pid
    ret = GetProcessName(pstProcData->pid, (char *)pcDefPath, pstProcData->procname);
    if(ret != 0) LOG_ERROR("get tcp process name failed by default pid! pid : %d, %s.", pstProcData->pid, PrintAddress(mnt));
    //print information

    return ret;
}

static char *encode_gateway(DATA_HEAD *data)
{
    int i;
    ROUTE_INFO *pstRtInfo;
    cJSON *root = NULL, *subobj = NULL;
    struct in_addr gate;
    char  *retstr = NULL;
    char ipv4[INET_ADDRSTRLEN];
    //check argument
    if(!data) return NULL;
    //create json object
    root = cJSON_CreateArray();
    if(!root) GOTO_ERROR(err, "create json new object failed!");
    //list
    for(i = 0; i < data->length; i++)
    {
        subobj = cJSON_CreateObject();
        if(!subobj) GOTO_ERROR(err, "create json new object failed!");
        //
        pstRtInfo = (ROUTE_INFO *)data->data;
        pstRtInfo += i;
        gate.s_addr = pstRtInfo->gateWay;
        memset(ipv4, 0, sizeof(ipv4));
        sprintf(ipv4, "%s", inet_ntoa(gate));
        cJSON_AddStringToObject(subobj, "gateway", ipv4);
        cJSON_AddStringToObject(subobj, "ifName", pstRtInfo->ifName);
        //add to root
        cJSON_AddItemToArray(root, subobj);
    }
    //
    retstr = cJSON_PrintUnformatted(root);
    //
    free(data->data);
    if(root != NULL) cJSON_Delete(root);
    return retstr;
err:
    if(data->data) free(data->data);
    if(root != NULL) cJSON_Delete(root);
    return NULL;
}

static char *get_container_info()
{
    int ret = 0, i;
    char *str;
    DATA_HEAD   data;
    IF_INFO     *pstIf;
    LISTEN_PORT *pstLport;
    DEFAULT_ROUTE *pstDefRoute;
    cJSON *root = NULL, *subobj, *param;
    //create json object
    root = cJSON_CreateObject();
    if(!root) GOTO_ERROR(err, "create json new object failed!");
    //put listen port
    subobj = cJSON_CreateArray();
    if(!subobj) GOTO_ERROR(err, "create json new array failed!");
    //get listen port
    ret = get_listen_port(&data, "");
    if(ret != 0) LOG_ERROR("get listen port infor failed.");
    for(i = 0; i < data.length; i++)
    {
        pstLport  = (LISTEN_PORT *)data.data;
        pstLport += i;
        param = cJSON_CreateObject();
        if(!param) CONTINUE_ERROR("create json new object failed!");
        cJSON_AddNumberToObject(param, "port", pstLport->port);
        cJSON_AddNumberToObject(param, "proto", pstLport->proto);
        //LOG_PRINT("listen port : %d, proto : %s.", pstLport->port, (pstLport->proto == IPPROTO_TCP) ? "tcp" : "udp");
        //add to array
        cJSON_AddItemToArray(subobj, param);
    }
    free(data.data);
    //add to root
    cJSON_AddArrayToObject(root, subobj);
    //get default gateway
    ret = get_default_gateway(&data, "");
    if(ret != 0) LOG_ERROR("get default gateway infor failed.");
    for(i = 0; i < data.length; i++)
    {
        pstDefRoute = (DEFAULT_ROUTE *)data.data;
        pstDefRoute += i;
        //LOG_PRINT("default gateway : %s, ifname : %s.", pstDefRoute->gateway, pstDefRoute->ifName);
        cJSON_AddStringToObject(root, "gateway", pstDefRoute->gateway);
        break;
    }
    free(data.data);
    //get default gateway
    ret = get_dev_name(&data, "");
    if(ret != 0) LOG_ERROR("get dev name infor failed.");
    for(i = 0; i < data.length; i++)
    {
        pstIf = (IF_INFO *)data.data;
        pstIf += i;
        //LOG_PRINT("if : %s, ipv4 : %s, ipv6 : %s, mac : %s.", pstIf->ifName, pstIf->ipv4, pstIf->ipv6, pstIf->mac);
        cJSON_AddStringToObject(root, "dev", pstIf->ifName);
        cJSON_AddStringToObject(root, "mac", pstIf->mac);
        if(strlen(pstIf->ipv4) > 0) cJSON_AddStringToObject(root, "ipv4", pstIf->ipv4);
        if(strlen(pstIf->ipv6) > 0) cJSON_AddStringToObject(root, "ipv6", pstIf->ipv6);
        break;
    }
    free(data.data);
    //
    str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    
    return str;
err:
    if(root) cJSON_Delete(root);

    return NULL;
}

int ParseRcvData(int fd, char *buf)
{
    int ret, length;
    char result[1024], *retdata = NULL, *str = NULL;
    PidAssMnt mnt;
    DATA_HEAD data;
    ProcessData stProcData;
    if((fd <= 0) || (!buf)) RETURN_ERROR(-2, "[setns] parse failed by argumnet is error!");
    //set 0
    memset(result, 0, sizeof(result));
    memset(&stProcData, 0, sizeof(stProcData));
    //parse json
    ret = ParseRcvJson(buf, &mnt);
    if(ret < 0) GOTO_ERROR(out, "[setns] parse receive json failed!");
    //init buf
    memset(result, 0, sizeof(result));
    //condition
    switch (mnt.dataType)
    {
         case DATA_SETNS:
            //set ns
            ret = SetNs(mnt.pid);
            if(ret < 0) goto out;
            //get process data
            ret = GetProcessData(&mnt, &stProcData);
            //if(ret != 0) LOG_ERROR("get process failed! ret : %d, %s.", ret,  PrintAddress(&mnt));
            goto out;
        
        case DATA_EBPF:
            //set default response data
            memcpy(result, "[]", sizeof(result));
            //init response data
            retdata = result;
            //get ebpf map data
            str = lookup_ebpf_map();
            if(str) retdata = str;
            goto rsp;

         case DATA_FILTER:
            return parse_filter_condition(buf);
        
        case DATA_EBPF_STATE:
            //parse json
            ret = parse_get_ebpf_state(buf, result, sizeof(result));
            if(ret != 0) LOG_ERROR("parse get ebpf state failed.");
            //move point
            retdata = result;
            goto rsp;
        
        case DATA_HOST_GATEWAY:
            //set default response data
            memcpy(result, "[]", sizeof(result));
            //init response data
            retdata = result;
            //get gateway
            ret = get_gateway(&data);
            if(ret != 0) GOTO_ERROR(rsp, "get gateway infor failed.");
            //encode gateway
            str = encode_gateway(&data);
            if(str) retdata = str;
            goto rsp;

        case DATA_CONTAINER:
            //set default response data
            memcpy(result, "{}", sizeof(result));
            //init response data
            retdata = result;
            //setns
            ret = SetNs(mnt.pid);
            if(ret < 0) goto rsp;
            //get container infor
            str = get_container_info();
            if(str) retdata = str;
            //set local mnt
            ret = SetLocalMntNs(szLocalMntNsFd);
            if(ret != 0) LOG_ERROR("set local mnt ns failed!");
            goto rsp;

        default:
            LOG_ERROR("data type is error, datatype : %d.", mnt.dataType);
            break;
    }

out:
    //set local mnt
    ret = SetLocalMntNs(szLocalMntNsFd);
    if(ret != 0) LOG_ERROR("set local mnt ns failed!");
    //pack data
    ret = ResultPack(&mnt, &stProcData, result);
    if(ret < 0) return 0;
    retdata = result;
rsp:
    //data len
    length = strlen(retdata);
    //print debug log
    //LOG_PRINT("rsp data : %s.", retdata);
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
    ret = OpenLocalMntNs();
    if(ret != 0) RETURN_ERROR(ret, "open local mnt ns failed.");
    //epoll fd
    epfd = epoll_create(256);
    if(epfd <= 0)
    {
        LOG_ERROR("create epoll fd failed, %s.", strerror(errno));
        goto err;
    }
    //create socket
    zListenFd = socket(PF_UNIX, SOCK_STREAM, 0);
    if(zListenFd <= 0) GOTO_ERROR(err, "create unix socket failed! %s.", strerror(errno));
    //socket address
    svrAddr.sun_family = AF_UNIX;
    strcpy(svrAddr.sun_path, DAEMON_UNIX);
    unlink(DAEMON_UNIX);
    //bind socket address
    ret = bind(zListenFd, (struct sockaddr *)&svrAddr, sizeof(svrAddr));
    if(ret < 0) GOTO_ERROR(err, "bind server unix socket failed, %s!", strerror(errno));
    //listen sockfd
    ret = listen(zListenFd, 1);
    if(ret < 0) GOTO_ERROR(err, "listen the client connect request! err : %s.", strerror(errno));
    //register epoll event
    ev.data.fd = zListenFd;
    ev.events = EPOLLIN;
    ret = epoll_ctl(epfd, EPOLL_CTL_ADD, zListenFd, &ev);
    if(ret < 0) GOTO_ERROR(err, "epoll ctl failed, %s.", strerror(errno));
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
                if(zClientFd <= 0) CONTINUE_ERROR("accept a new client failed, %s.", strerror(errno));
                //epoll event
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
