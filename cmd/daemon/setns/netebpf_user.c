/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/resource.h>
#include <pthread.h>
#include <sys/utsname.h>

#include "bpf_load.h"
#include "bpf_util.h"
#include "cjson.h"
#include "netebpf_user.h"


static UINT timestamp = 0;
static int use_ebpf = 0;

struct proc_info {
    UINT  pid;
    UCHAR comm[32];
} __attribute__((packed));

struct net_addr {
    UCHAR  proto;
    USHORT sport;
    USHORT dport;
    UINT   saddr;
    UINT   daddr;
} __attribute__((packed));

int get_kernel_release(int *a, int *b, int *c)
{
    static char buf[32];
    struct utsname u;
    int num;
    int ret = uname(&u);
    if(ret < 0)
    {
        LOG_ERROR("get kernel version failed, %s.", strerror(errno));
        return -1;
    }
    //init
    memset(buf, 0, sizeof(buf));
    //get version
    num = sscanf(u.release, "%d.%d.%d-", a, b, c);
    if(num != 3)
    {
       LOG_ERROR("get kernel version failed by sscanf.");
        return -1; 
    }
    //print log
    //LOG_PRINT("kernel version : %d.%d.%d", *a, *b, *c);
    //return
    return 0;
}

int is_support_ebpf()
{
    int a, b, c;
    //get kernel version
    int ret = get_kernel_release(&a, &b, &c);
    if(ret != 0) return ret;
    //compare version
    if(a != 5) return -2;

    return 0;
}

int data_to_json(cJSON *root, struct net_addr *key, struct proc_info *value)
{
    cJSON *subobj = NULL;
    if(!root || !key || !value) return -1;
    //create sub json
    subobj = cJSON_CreateObject();
    if(!subobj)
    {
        LOG_ERROR("create json new object failed!");
        return -1;
    }
    //to object
    cJSON_AddNumberToObject(subobj, "proto",     key->proto);
    cJSON_AddNumberToObject(subobj, "sport",     key->sport);
    cJSON_AddNumberToObject(subobj, "saddr",     key->saddr);
    cJSON_AddNumberToObject(subobj, "dport",     key->dport);
    cJSON_AddNumberToObject(subobj, "daddr",     key->daddr);
    cJSON_AddNumberToObject(subobj, "pid",       value->pid);
    cJSON_AddNumberToObject(subobj, "status",    MATCH_SUCC);
    cJSON_AddStringToObject(subobj, "proc_name", value->comm);
    //add to root
    cJSON_AddItemToArray(root, subobj);
    return 0;
}

static int get_ebpf_enable_state(char *buf)
{
    int  ret = -1;
    UINT value;
    cJSON *root, *item, *data;
    if(!buf) return ret;
    //parse json
    root = cJSON_Parse(buf);
    if(!root)
    {
        LOG_ERROR("parse enable state json failed!");
        goto end;
    }
    //get data type
    item = cJSON_GetObjectItem(root, "enable");
    if(!item)
    {
        LOG_ERROR("get enable item failed!");
        goto end;
    }
    //get enable state
    ret = item->valueint;

end:
    //free resource
    cJSON_Delete(root);
    return ret;
}

int parse_get_ebpf_state(char *src, char *dst, int buflen)
{
    char *str = NULL;
    int datalen, ret;
    cJSON *root = NULL;
    if(!dst) return 0;
    //get enable state
    ret = get_ebpf_enable_state(src);
    if(ret > 0)
    {
        //ebbp init
        ebpf_start();
    }
    //parse json
    root = cJSON_CreateObject();
    if(!root)
    {
        LOG_ERROR("parse filter condition json failed!");
        goto err;
    }
    //ebpf state
    cJSON_AddNumberToObject(root, "ebpf_state", get_ebpf_state());
    //json to string
    str = cJSON_PrintUnformatted(root);
    if(!str)
    {
        LOG_ERROR("json to string failed.");
        goto err;
    }
    //dat len
    datalen = strlen(str);
    if(datalen >= buflen)
    {
        LOG_ERROR("dst buf is small. data len : %d, dst buf len : %d.", datalen, buflen);
        goto err;
    }
    //memcpy
    memcpy(dst, str, datalen);
    //free
    cJSON_Delete(root);
    free(str);
    return 0;

err:
    if(root) cJSON_Delete(root);
    if(str) free(str);
    //set default data
    memcpy(dst, "{\"ebpf_state\":0}", buflen);
    return -1;
}

static int set_filter_condition(UINT key)
{
    UCHAR value = 0;
    int fd = map_fd[2];
    int ret = bpf_map_update_elem(fd, &key, &value, BPF_NOEXIST);
    if(ret != 0) LOG_WARN("set filter condition failed, %s.", strerror(errno));
    return ret;
}

int parse_filter_condition(char *buf)
{
    int  num, i;
    UINT value;
    cJSON *root, *item, *data;
    if(!buf) return 0;
    //parse json
    root = cJSON_Parse(buf);
    if(!root)
    {
        LOG_ERROR("parse filter condition json failed!");
        goto end;
    }
    //get data type
    item = cJSON_GetObjectItem(root, "addrs");
    if(!item)
    {
        LOG_ERROR("get addrs item failed!");
        goto end;
    }
    //get array
    num = cJSON_GetArraySize(item);
    //set filter condition
    for(i = 0; i < num; i++)
    {
        data = cJSON_GetArrayItem(item, i);
        value = (UINT)data->valuedouble;
        //set filter conditon
        set_filter_condition(value);
    }

end:
    //free resource
    cJSON_Delete(root);
    return 0;
}

//need free result
char *lookup_ebpf_map()
{
    char  *retstr = NULL;
    cJSON *root = NULL;
    int ret, fd = map_fd[1];
    struct proc_info value;
    struct net_addr key, next_key;
    //is support ebpf
    if(get_ebpf_state() != EBPF_SUCC) return NULL;
    //init
    memset(&key, 0, sizeof(key));
    //create json object
    root = cJSON_CreateArray();
    if(root == NULL)
    {
        LOG_ERROR("create json new object failed!");
        return NULL;
    }
    //lookup ebpf map
    while (bpf_map_get_next_key(fd, &key, &next_key) == 0)
    {
        key = next_key;
        bpf_map_lookup_elem(fd, &next_key, &value);
        //to json
        ret = data_to_json(root, &next_key, &value);
        if(ret != 0)
        {
            LOG_WARN("net data to json failed!");
            goto end;
        }
        //delete data
        bpf_map_delete_elem(fd, &next_key);
    }

end:
    //data format
    retstr = cJSON_PrintUnformatted(root);
    //free memory
    if(root != NULL) cJSON_Delete(root);
    //return
    return retstr;
}

void print_ebpf_map_info(struct net_addr *key, struct proc_info *value)
{
    char saddr[16], daddr[16];
    //proto
    char *proto = (key->proto == IPPROTO_TCP) ? "tcp" : ((key->proto == IPPROTO_UDP) ? "udp" : "null");
    //init
    memset(saddr, 0, sizeof(saddr));
    memset(daddr, 0, sizeof(daddr));
    inet_ntop(AF_INET, (void *)&key->saddr, saddr, sizeof(saddr));
    inet_ntop(AF_INET, (void *)&key->daddr, daddr, sizeof(saddr));
    //print information
    LOG_PRINT("%s %s:%d => %s:%d  pid : %u, comm : %s.", proto, saddr, key->sport, daddr, key->dport, value->pid, value->comm);
}

void *prevent_ebpf_map_overflow()
{
    int fd = map_fd[1];
    UINT count;
    UINT interval = 60 * 10;
    struct proc_info value;
    struct net_addr key, next_key;

    while(1)
    {
        sleep(10);
        if((timestamp - time(0)) < interval) continue;
        //count init
        count = 0;
        //key init
        memset(&key, 0, sizeof(key));
        //statistics
        while (bpf_map_get_next_key(fd, &key, &next_key) == 0)
        {
			key = next_key;
            //count
            count++;
            //bpf_map_lookup_elem(fd, &next_key, &value);
        }
		
        //warn
        if(count > 15000) LOG_WARN("ebpf map data is more, count : %u.", count);
    }
}

int ebpf_load_file(char *filename)
{
    int ret;
    pthread_t ebpfmap;
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};

    if(!filename)
    {
        LOG_ERROR("ebpf kernel file is null!");
        return -1;
    }
    //set rlimit
    ret = setrlimit(RLIMIT_MEMLOCK, &r);
    if(ret != 0)
    {
        LOG_ERROR("set rlimit failed, %s.", strerror(errno));
        return -1;
    }
    //load file
    ret = load_bpf_file(filename);
    if(ret != 0)
    {
        LOG_ERROR("load %s failed, %s, %s.", filename, strerror(errno), bpf_log_buf);
        return -1;
    }
    //now time
    timestamp = time(0);
    //get net data from ebpf map
    ret = pthread_create(&ebpfmap, NULL, prevent_ebpf_map_overflow, NULL);
    if(ret != 0)
    {
        LOG_ERROR("create get ebpf data pthread failed, %s.", strerror(errno));
        return -1;
    }

    return 0;
}

//get ebpf state
int get_ebpf_state() {return use_ebpf;}

//set ebpf state
void set_ebpf_state(int state) {use_ebpf = state;}

//ebpf start
int ebpf_start()
{
    int ret;
    char ebpf_file[] = "ubuntu5.4.0_kern.o";
    //ebpf state init
    set_ebpf_state(0);
    //judgment
    ret = is_support_ebpf();
    if(ret != 0) return 0;
    //support ebpf
    ret = ebpf_load_file(ebpf_file);
    if(ret != 0) return 0;
    //ebpf start
    set_ebpf_state(EBPF_SUCC);
    //return
    return 0;
}
