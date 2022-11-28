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

#define LOG_ERROR(fmt, ...) {\
    printf("[ERROR] [line:%d] [%s] " fmt "\n", __LINE__, __FUNCTION__, ##__VA_ARGS__);\
}

#define LOG_PRINT(fmt, ...) {\
    printf("[INFO] [line:%d] [%s] " fmt "\n", __LINE__, __FUNCTION__, ##__VA_ARGS__);\
}

#define LOG_WARN(fmt, ...) {\
    printf("[WARN] [line:%d] [%s] " fmt "\n", __LINE__, __FUNCTION__, ##__VA_ARGS__);\
}

#define RETURN_ERROR(ret, fmt, ...) {\
    printf("[WARN] [line:%d] [%s] " fmt "\n", __LINE__, __FUNCTION__, ##__VA_ARGS__);\
    return ret;\
}

#define BREAK_ERROR(fmt, ...) {\
    printf("[WARN] [line:%d] [%s] " fmt "\n", __LINE__, __FUNCTION__, ##__VA_ARGS__);\
    break;\
}

#define CONTINUE_ERROR(fmt, ...) {\
    printf("[WARN] [line:%d] [%s] " fmt "\n", __LINE__, __FUNCTION__, ##__VA_ARGS__);\
    continue;\
}

#define GOTO_ERROR(state, fmt, ...) {\
    printf("[WARN] [line:%d] [%s] " fmt "\n", __LINE__, __FUNCTION__, ##__VA_ARGS__);\
    goto state;\
}


static int szLocalMntNsFd = 0;

int GetLocalProcessName(int pid, const char *basepath, char procname[128])
{
    int fd, ret;
    char path[36];
    if((pid == 0) || (!procname)) return -2;

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
        ret = GetLocalProcessName(pid, "", comm);
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

int GetProcessName(int pid, const char *basepath, char procname[128])
{
    int fd, ret;
    char path[36];
    if((pid == 0) || (!procname)) return -2;

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

int OpenLocalMntNs()
{
    int ret, pid = 0;
    char *path = "/proc/%d/ns/mnt";
    char buff[128] = {0};
    //
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

int SetNs(int pid, char *BasePath)
{
    int fd = 0, ret;
    char path[128];
    if(pid <= 0) RETURN_ERROR(-1, "pid is error!");
    //set local mnt
    ret = SetLocalMntNs(szLocalMntNsFd);
    if(ret != 0) RETURN_ERROR(ret, "set local mnt ns failed!");
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

int main(int argc, char *argv[])
{
    int ret, pid = 0;
    if(argc != 3) RETURN_ERROR(-1, "need pid and path.");
    //pid
    pid = atoi(argv[1]);
    if(pid <= 0) RETURN_ERROR(-1, "pid is error, please correct pid.");

    //open local mnt namespaces
    ret = OpenLocalMntNs();
    if(ret != 0) RETURN_ERROR(ret, "open local mnt ns failed.");
    //
    ret = ReadFileList("/");
    if(ret != 0) GOTO_ERROR(err, "read file list failed.");
    //set ns
    ret = SetNs(pid, argv[2]);
    if(ret < 0) GOTO_ERROR(err, "setns to %d failed.", pid);
    //
    ret = ReadFileList("/");
    if(ret != 0) GOTO_ERROR(err, "read file list failed.");
    //
    ret = SetLocalMntNs(szLocalMntNsFd);
    if(ret != 0) GOTO_ERROR(err, "set local mnt ns failed.");
    //
    ret = ReadFileList("/");
    if(ret != 0) GOTO_ERROR(err, "read file list failed.");
    //set ns
    ret = SetNs(pid, argv[2]);
    if(ret < 0) GOTO_ERROR(err, "setns to %d failed.", pid);
    //
    ret = ReadFileList("/");
    if(ret != 0) GOTO_ERROR(err, "read file list failed.");
    //close
    close(szLocalMntNsFd);
    return 0;
err:
    if(szLocalMntNsFd > 0) close(szLocalMntNsFd);
    return -1;
}
