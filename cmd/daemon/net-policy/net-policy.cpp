#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h> /* for NF_ACCEPT */
#include <errno.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <set>
#include <vector>
#include <string.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <dirent.h>
#include <fcntl.h>
#include <sched.h>
#include "net-policy.h"

using namespace std;

struct u32_mask
{
    uint32_t value;
    uint32_t mask;
};

typedef struct nf_conntrack NF_CONNTRACK;
/*static value*/
static int szLocalNetNsFd = 0;
static int gClientFd = 0;
static int gPostLinkFd = 0;
static set<int> MaskCidr;
static set<int> Priority;
static map<uint64_t, NFQ_RES_INFO *> NfqueResData;
static map<string, RULE_DETAIL> NetInputPolicyRule;
static map<string, RULE_DETAIL> NetOutputPolicyRule;
static map<string, map<string, FLOW_DIR>*> NetPolicyKey;

void PrintPolicyData(RULE_DETAIL &r, RULE_PORT &stPort)
{
    if(gzLogLevel > 0) {
        fprintf(stderr, "[policy] name : %s, dir : %d, action : %d, priority : %d, proto : %d, ip : %s <--> %s port : %d ~ %d\n",
            r.policyKey.c_str(), r.direction, r.action, r.priority, r.proto, r.srcIp.c_str(), r.dstIp.c_str(), stPort.port, stPort.endPort);
    }
}

std::string PrintPortsData(std::vector<RULE_PORT> &ports)
{
    std::string value = "";
    if(gzLogLevel > 0) 
    {
        for(int p = 0; p < (int)ports.size(); p++)
        {
            value += std::to_string(ports.at(p).port);
            value += " ~ ";
            value += std::to_string(ports.at(p).endPort);
            if(p != ((int)ports.size() - 1)) value += ", ";
        }
    }
    return value;
}

int OpenLocalNetNs()
{
    const char *path = "/proc/self/ns/net";
    //open net namespaces
    szLocalNetNsFd = open(path, O_RDONLY);
    if(szLocalNetNsFd <= 0) RETURN_ERROR(-1, "open %s net namespaces failed! err : %s.", path, strerror(errno));
    return 0;
}

int SetLocalNetNs(int fd)
{
    int ret;
    if(fd <= 0) RETURN_ERROR(-1, "local net ns fd is error!!");
    //unshare net
    ret = unshare(CLONE_NEWNET);
    if(ret != 0) RETURN_ERROR(-1, "unshare net failed! err : %s.", strerror(errno));
    //set local net ns
    ret = setns(fd, CLONE_NEWNET);
    if(ret != 0) RETURN_ERROR(-1, "set local net ns failed! err : %s.", strerror(errno));

    return 0;
}

string ipv6Convert(char *ipv6)
{
    int ret;
    string sRet = "";
    unsigned char addr[INET6_ADDRSTRLEN];
    ret = inet_pton(AF_INET6, ipv6, &(addr));
    if(ret <= 0) RETURN_ERROR(sRet, "format ipv6 address failed, ipv6 : %s.", ipv6);
    sRet = (char *)addr;
    return sRet;
}

void ipv4CidrToIp(string cidr, string &ip, int &mask)
{
    struct in_addr addr;
    uint32_t uzIpaddr, uzMask;
    size_t index;
    string sip, smask;
    smask = "32";
    sip = cidr;
    index = cidr.find("/");
    if(index != string::npos)
    {
        sip = cidr.substr(0, index);
        smask = cidr.substr(index + 1);
    }
    uzIpaddr = ntohl(inet_addr(sip.c_str()));
    uzMask   = atoi(smask.c_str());
    mask     = uzMask;
    uzMask   = ~0 << (32 - uzMask);
    /*count network address*/
    uzIpaddr &= uzMask;
    addr.s_addr = htonl(uzIpaddr);
    ip = inet_ntoa(addr);
}

string ipv4CidrToIp(string ip, int mask)
{
    struct in_addr addr;
    uint32_t uzIpaddr, uzMask;
    uzIpaddr = ntohl(inet_addr(ip.c_str()));
    uzMask   = ~0 << (32 - mask);
    /*count network address*/
    uzIpaddr &= uzMask;
    addr.s_addr = htonl(uzIpaddr);
    return inet_ntoa(addr);
}

static string CreatePolicyRuleKey(RULE_DETAIL &info)
{
    int mask;
    string key, ip;
    char buff[128] = {0};
    switch (info.direction)
    {
        case DIR_INGRESS:
            ipv4CidrToIp(info.srcIp, ip, mask);
            /*create key*/
            sprintf(buff, "%d-%d-%s-%s", info.priority, info.proto, ip.c_str(), info.dstIp.c_str());
            break;
        case DIR_EGRESS:
            ipv4CidrToIp(info.dstIp, ip, mask);
            /*create key*/
            sprintf(buff, "%d-%d-%s-%s", info.priority, info.proto, info.srcIp.c_str(), ip.c_str());
            break;
        default:
            return key;
    }
    /*save cidr*/
    if((mask > 0) && (mask <= 32)) MaskCidr.insert(mask);
    /*save priority*/
    Priority.insert(info.priority);
    /*print debug log*/
    LOG_D("create policy rule key : [%s], priority : %d, priority size : %d", buff, info.priority, (int)Priority.size());
    key = buff;
    return key;
}

string ipv4ToString(uint32_t ip)
{
    struct in_addr addr;
    addr.s_addr = ip;
    return inet_ntoa(addr);
}

static int CreatePolicyRuleKey(FIVE_TUPLE &tuple, FLOW_DIR dir, vector<string> &value)
{
    char buff[128] = {0};
    vector<string> srcaddr, dstaddr;
    /*init*/
    value.clear();
    /*create key*/
    for(auto it = Priority.begin(); it != Priority.end(); ++it)
    {
        for(auto iter = MaskCidr.begin(); iter != MaskCidr.end(); ++iter)
        {
            switch (dir)
            {
                case DIR_INGRESS:
                    srcaddr.push_back("0.0.0.0");
                    srcaddr.push_back(ipv4CidrToIp(tuple.srcAddr, *iter));
                    dstaddr.push_back(tuple.dstAddr);
                    break;
                case DIR_EGRESS:
                    srcaddr.push_back(tuple.srcAddr);
                    dstaddr.push_back("0.0.0.0");
                    dstaddr.push_back(ipv4CidrToIp(tuple.dstAddr, *iter));
                    break;
                default:
                    return -1;
            }
            //list priority
            for(size_t i = 0; i < srcaddr.size(); i++)
            {
                for(size_t j = 0; j < dstaddr.size(); j++)
                {
                    memset(buff, 0, sizeof(buff));
                    sprintf(buff, "%d-%d-%s-%s", *it, tuple.proto, srcaddr.at(i).c_str(), dstaddr.at(j).c_str());
                    /*print debug log*/
                    //if(tuple.dstPort == 80) LOG_D("rule key : [%s]", buff);
                    /*save key*/
                    value.push_back(buff);
                    //all protocol
                    memset(buff, 0, sizeof(buff));
                    sprintf(buff, "%d-0-%s-%s", *it, srcaddr.at(i).c_str(), dstaddr.at(j).c_str());
                    /*save key*/
                    value.push_back(buff);
                    /*print debug log*/
                    //if(tuple.dstPort == 80) LOG_D("rule key : [%s]", buff);
                }
            }
            /*clear data*/
            dstaddr.clear();
            srcaddr.clear();
        }
    }
    return 0;
}

int SetNs(int pid, char *basePath)
{
    int fd = 0, ret;
    char path[128];
    if(pid <= 0) RETURN_ERROR(-1, "pid is error!");
    //path
    memset(path, 0, sizeof(path));
    sprintf(path, "%s/proc/%d/ns/net", basePath, pid);
    //open path
    fd = open(path, O_RDONLY);
    if(fd <= 0) RETURN_ERROR(-1, "open %s failed, err : %s.", path, strerror(errno));
    //unshare net
    ret = unshare(CLONE_NEWNET);
    if(ret != 0) GOTO_ERROR(err, "unshare net failed! err : %s.", strerror(errno));
    //set net ns
    ret = setns(fd, CLONE_NEWNET);
    if(ret != 0) GOTO_ERROR(err, "set net ns failed, path : %s, err : %s.", path, strerror(errno));
    //close fd
    close(fd);
    //return
    return 0;
err:
    if(fd > 0) close(fd);
    return -1;
}

/*post match message*/
static int PostMatchMsg(FIVE_TUPLE &tuple, NET_POLICY_RULE rule, FLOW_DIR dir, string &sRuleKey)
{
    int ret, len;
    char *str = NULL;
    cJSON *root = NULL;
    if(gPostLinkFd <= 0) return 0;
    //rule
    rule = (rule == NET_DEFAULT) ? NET_ALLOW : rule;
    //create json object
    root = cJSON_CreateObject();
    if(!root) RETURN_ERROR(-1, "create json object failed.");
    cJSON_AddNumberToObject(root, "proto", tuple.proto);
    cJSON_AddNumberToObject(root, "rule", rule);
    cJSON_AddNumberToObject(root, "direction", dir);
    cJSON_AddNumberToObject(root, "src-port", tuple.srcPort);
    cJSON_AddNumberToObject(root, "dst-port", tuple.dstPort);
    cJSON_AddStringToObject(root, "src-ip", tuple.srcAddr.c_str());
    cJSON_AddStringToObject(root, "dst-ip", tuple.dstAddr.c_str());
    cJSON_AddStringToObject(root, "policy_name", sRuleKey.c_str());
    str = cJSON_PrintUnformatted(root);
    if(!str) GOTO_ERROR(err, "json format failed.");
    /*data len*/
    len = (int)strlen(str);
    /*send data*/
    ret = write(gPostLinkFd, str, len);
    if(ret <= 0) GOTO_ERROR(err, "post match msg to server failed, %s.", strerror(errno));
    /*free*/
    cJSON_Delete(root);
    free(str);
    return 0;
err:
    if(root) cJSON_Delete(root);
    if(str) free(str);
    return -1;
}

/*math net policy rule*/
static NET_POLICY_RULE MatchNetPolicyRule(FIVE_TUPLE &tuple, FLOW_DIR dir, string &sRuleKey)
{
    int p;
    bool bIsMatch;
    string key;
    vector<string> ruleKeys;
    map<string, RULE_DETAIL> *ruleQue;
    map<string, RULE_DETAIL>::iterator it;
    /*match*/
    ruleQue = (dir == DIR_INGRESS) ? &NetInputPolicyRule : &NetOutputPolicyRule;
    if(ruleQue->size() == 0) return NET_DEFAULT;
    /*get rule key*/
    CreatePolicyRuleKey(tuple, dir, ruleKeys);
    //print debug log
    //LOG_D("create rule key num : %lu.", ruleKeys.size());
    for(int i = 0; i < (int)ruleKeys.size(); i++)
    {
        //print debug log
        //LOG_D("%s, find rule, key : %s, dst port : %d.", (dir == DIR_INGRESS) ? "ingress" : "egress", ruleKeys[i].c_str(), tuple.dstPort);
        //find rule
        it = ruleQue->find(ruleKeys.at(i).c_str());
        if(it == ruleQue->end()) continue;
        //print debug log
        LOG_D("i : %d, match %s rule key, key : %s, tuple proto : %d, dst port : %d, vPorts size : %d, %s.", 
            i, (dir == DIR_INGRESS) ? "ingress" : "egress", ruleKeys.at(i).c_str(), tuple.proto, tuple.dstPort, (int)it->second.vPorts.size(), PrintPortsData(it->second.vPorts).c_str());
        /*match protocol*/
        if(!((it->second.proto == 0) || (tuple.proto == it->second.proto))) break;
        /*port*/
        auto rulePorts = it->second.vPorts;
        bIsMatch = (rulePorts.size() == 0) ? true : false;
        /*match port*/
        for(p = 0; p < (int)rulePorts.size(); p++)
        {
            if(rulePorts.at(p).endPort == 0) {
                bIsMatch = true;
                break;
            }
            /*check port rang*/
            if(tuple.dstPort > rulePorts.at(p).endPort) continue;
            /*check min port*/
            if(tuple.dstPort < rulePorts.at(p).port) continue;
            /*set match true*/
            bIsMatch = true;
            /*break*/
            break;
        }
        /*break*/
        if(!bIsMatch) continue;
        //print debug log
        LOG_D("[policy] match %s name : %s, dir : %d, action : %d, priority : %d, proto : %d, ip : %s <--> %s port : %d ~ %d\n",
            (dir == DIR_INGRESS) ? "ingress" : "egress", it->second.policyKey.c_str(), it->second.direction, 
            it->second.action, it->second.priority, it->second.proto, it->second.srcIp.c_str(), it->second.dstIp.c_str(), rulePorts.at(p).port, rulePorts.at(p).endPort);
        //rule policy key
        sRuleKey = it->second.policyKey;
        //reverse selection
        return it->second.action;
    }

    return NET_DEFAULT;
}

/*update session callback*/
static int UpdateNetSession(NFC_MSG_TYPE type, NF_CONNTRACK *ct, void *data)
{
    int ret;
    uint32_t mark;
    struct nfct_handle *ith = NULL;
    NFQ_RES_INFO *nfqres = (NFQ_RES_INFO *)data;
    NF_CONNTRACK *obj, *tmp = NULL;
    /*check argument*/
    if(!ct || !data) return NFCT_CB_CONTINUE;
    //
    obj = (NF_CONNTRACK *)nfqres->nfct;
    /*compare nfct*/
    if(!nfct_cmp(obj, ct, NFCT_CMP_ORIG)) return NFCT_CB_CONTINUE;
    /*get mark*/
    mark = nfct_get_attr_u32(obj, ATTR_MARK);
    if(mark > 100) return NFCT_CB_CONTINUE;
    /*new nfct*/
    tmp = (NF_CONNTRACK *)nfqres->nfctCb;
    if (!tmp) RETURN_ERROR(NFCT_CB_CONTINUE, "new nfct failed.");
    /*open nfct*/
    ith = (struct nfct_handle *)nfqres->nfctCbHd;
    if(!ith) RETURN_ERROR(NFCT_CB_CONTINUE, "open nfct failed.");
    /*copy info*/
    nfct_copy(tmp, ct, NFCT_CP_ORIG);
    //nfct_copy(tmp, obj, NFCT_CP_META);
    /*set mark*/
    nfct_set_attr_u32(tmp, ATTR_MARK, mark);
    /* do not send NFCT_Q_UPDATE if ct appears unchanged */
    if (nfct_cmp(tmp, ct, NFCT_CMP_ALL | NFCT_CMP_MASK)) return NFCT_CB_CONTINUE;
    /*query*/
    ret = nfct_query(ith, NFCT_Q_UPDATE, tmp);
    if (ret < 0) LOG_E("Operation failed: update mark failed.")
    /*return*/
    return NFCT_CB_CONTINUE;
}

/*set mark to accept*/
static int SetAcceptMark(NFQ_RES_INFO *nfqres, FIVE_TUPLE &tuple, NFC_MSG_TYPE msgtype, int markValue)
{
    int ret, family = AF_INET;
    NF_CONNTRACK *ct = NULL;
    struct nfct_handle *cth = NULL;
    if(!nfqres) RETURN_ERROR(-1, "nfct resource is nil.");
    /*new nfct*/
    ct  = (NF_CONNTRACK *)nfqres->nfct;
    if(!ct) RETURN_ERROR(-1, "nfct is null.");
    /*open nfct*/
    cth = (struct nfct_handle *)nfqres->nfctHd;
    if (!cth) RETURN_ERROR(-1, "nfct handle is nil.");
    /*set mark*/
    nfct_set_attr_u32(ct, ATTR_MARK, markValue);
    /*L3 proto*/
    nfct_set_attr_u8(ct, ATTR_ORIG_L3PROTO, family);
    /*set protocol*/
    if(tuple.proto > 0) nfct_set_attr_u8(ct, ATTR_L4PROTO, tuple.proto);
    //ip
    if(tuple.srcAddr.length() > 0) nfct_set_attr_u32(ct, ATTR_ORIG_IPV4_SRC, inet_addr(tuple.srcAddr.c_str()));
    if(tuple.dstAddr.length() > 0) nfct_set_attr_u32(ct, ATTR_ORIG_IPV4_DST, inet_addr(tuple.dstAddr.c_str()));
    //port
    if(tuple.srcPort > 0) nfct_set_attr_u16(ct, ATTR_ORIG_PORT_SRC, htons(tuple.srcPort));
    if(tuple.dstPort > 0) nfct_set_attr_u16(ct, ATTR_ORIG_PORT_DST, htons(tuple.dstPort));
    //register
    //nfct_callback_register(cth, msgtype, UpdateNetSession, nfqres);
    /*query*/
    ret = nfct_query(cth, NFCT_Q_DUMP, &family);
    if(ret != 0) RETURN_ERROR(ret, "nfct query failed.");
    /*return*/
    return 0;
}

/*parse package*/
static int parse_package(unsigned char *pkg, FIVE_TUPLE &tuple)
{
    uint16_t srcPort, dstPort;
    struct iphdr  *iph;
    struct udphdr *udph;
    struct tcphdr *tcph;
    struct in_addr addr;
    /*init buffer*/
    iph = (struct iphdr *)pkg;
    addr.s_addr   = iph->saddr;
    tuple.srcAddr = inet_ntoa(addr);
    addr.s_addr   = iph->daddr;
    tuple.dstAddr = inet_ntoa(addr);
    if(iph->version != 4) return NF_ACCEPT;
    /*procotol*/
    switch (iph->protocol)
    {
        case IPPROTO_UDP:
            udph = (struct udphdr *)(pkg + iph->ihl * 4);
            srcPort = udph->source;
            dstPort = udph->dest;
            break;

        case IPPROTO_TCP:
            tcph = (struct tcphdr *)(pkg + iph->ihl * 4);
            srcPort = tcph->source;
            dstPort = tcph->dest;
            break;

        default:
            return NF_ACCEPT;
    }
    /*five tuple*/
    tuple.proto = iph->protocol;
    tuple.srcPort = ntohs(srcPort);
    tuple.dstPort = ntohs(dstPort);
    /*return*/
    return NF_MATCH_RULE;
}

static int input_nfq_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
    int id = 0, ret;
    uint32_t mark;
    string sRuleKey;
    struct nfqnl_msg_packet_hdr *ph;
    unsigned char *pkg;
    NET_POLICY_RULE ruleRet;
    FIVE_TUPLE tuple;
    NFQ_RES_INFO *nfqres = (NFQ_RES_INFO *)data;
    nfqres = nfqres;

    ph = nfq_get_msg_packet_hdr(nfa);
    if(!ph) return 0;

    id = ntohl(ph->packet_id);
    //printf("hw_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id);

    mark = nfq_get_nfmark(nfa);
    if(mark == NET_ALLOW) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

    ret = nfq_get_payload(nfa, &pkg);
    if (ret < 0) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    
    //printf("payload_len=%d ", ret);
    if(ret < (int)sizeof(struct iphdr)) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    
    ret = parse_package(pkg, tuple);
    if(ret != NF_MATCH_RULE) nfq_set_verdict(qh, id, ret, 0, NULL);
    /*print debug log*/
    LOG_V("input %s %s:%u -> %s:%u ", (tuple.proto == IPPROTO_UDP) ? "udp" : "tcp", tuple.srcAddr.c_str(), tuple.srcPort, tuple.dstAddr.c_str(), tuple.dstPort);
    /*match rule*/
    ruleRet = MatchNetPolicyRule(tuple, DIR_INGRESS, sRuleKey);
    if(ruleRet != NET_DEFAULT) PostMatchMsg(tuple, ruleRet, DIR_INGRESS, sRuleKey);
    //deny
    if(ruleRet == NET_DENY)
    {
        LOG_D("input drop %s %s:%u -> %s:%u ", (tuple.proto == IPPROTO_UDP) ? "udp" : "tcp", tuple.srcAddr.c_str(), tuple.srcPort, tuple.dstAddr.c_str(), tuple.dstPort);
        /*drop data*/
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }
    /*return*/
    return nfq_set_verdict2(qh, id, NF_ACCEPT, NET_ALLOW, 0, NULL);
}

static int output_nfq_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
    int id = 0, ret;
    uint32_t mark;
    string sRuleKey;
    struct nfqnl_msg_packet_hdr *ph;
    unsigned char *pkg;
    NET_POLICY_RULE ruleRet;
    FIVE_TUPLE tuple;
    NFQ_RES_INFO *nfqres = (NFQ_RES_INFO *)data;
    nfqres = nfqres;

    ph = nfq_get_msg_packet_hdr(nfa);
    if(!ph) return 0;

    id = ntohl(ph->packet_id);
    //printf("hw_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id);

    mark = nfq_get_nfmark(nfa);
    if(mark == NET_ALLOW) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

    ret = nfq_get_payload(nfa, &pkg);
    if (ret < 0) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    
    //printf("payload_len=%d ", ret);
    if(ret < (int)sizeof(struct iphdr)) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    
    ret = parse_package(pkg, tuple);
    if(ret != NF_MATCH_RULE) nfq_set_verdict(qh, id, ret, 0, NULL);
    /*print debug log*/
    LOG_V("output %s %s:%u -> %s:%u ", (tuple.proto == IPPROTO_UDP) ? "udp" : "tcp", tuple.srcAddr.c_str(), tuple.srcPort, tuple.dstAddr.c_str(), tuple.dstPort);
    /*match rule*/
    ruleRet = MatchNetPolicyRule(tuple, DIR_EGRESS, sRuleKey);
    if(ruleRet != NET_DEFAULT) PostMatchMsg(tuple, ruleRet, DIR_EGRESS, sRuleKey);
    //deny
    if(ruleRet == NET_DENY)
    {
        LOG_D("output drop %s %s:%u -> %s:%u ", (tuple.proto == IPPROTO_UDP) ? "udp" : "tcp", tuple.srcAddr.c_str(), tuple.srcPort, tuple.dstAddr.c_str(), tuple.dstPort);
        /*drop data*/
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }
    /*return*/
    return nfq_set_verdict2(qh, id, NF_ACCEPT, NET_ALLOW, 0, NULL);
}

/*destroy nfqueue resource*/
void DestroyNfqueResource(NFQ_RES_INFO *nfqres)
{
    struct nfq_q_handle *qh = NULL;
    if(!nfqres) return;

    if(nfqres->inputFd > 0) close(nfqres->inputFd);
    if(nfqres->outputFd > 0) close(nfqres->outputFd);
    if(nfqres->inputQue)
    {
        qh = (struct nfq_q_handle *)nfqres->inputQue;
        nfq_close(qh->h);
        nfq_destroy_queue(qh);
    }

    if(nfqres->outputQue)
    {
        qh = (struct nfq_q_handle *)nfqres->outputQue;
        nfq_close(qh->h);
        nfq_destroy_queue(qh);
    }
    if(nfqres->inputCb) delete (RCV_EPOLL_CB *)nfqres->inputCb;
    if(nfqres->outputcb) delete (RCV_EPOLL_CB *)nfqres->outputcb;
    if(nfqres->nfct) nfct_destroy((NF_CONNTRACK *)nfqres->nfct);
    if(nfqres->nfctCb) nfct_destroy((NF_CONNTRACK *)nfqres->nfctCb);
    if(nfqres->nfctHd) nfct_close((struct nfct_handle *)nfqres->nfctHd);
    if(nfqres->nfctCbHd) nfct_close((struct nfct_handle *)nfqres->nfctCbHd);
    /*delete pid*/
    NfqueResData.erase(nfqres->podId);
    //delete memory
    delete nfqres;
    /*print debug log*/
    LOG_D("free nfqueue resource!");
}

int OpenConntrack(NFQ_RES_INFO *nfqres)
{
    FIVE_TUPLE tuple = {};
    //nf conntrack
    nfqres->nfct = nfct_new();
    if(!nfqres->nfct) GOTO_ERROR(err, "new nf conntrack failed");
    nfqres->nfctHd = nfct_open();
    if(!nfqres->nfctHd) GOTO_ERROR(err, "open nf conntrack failed");
    //nf conntrack callback
    nfqres->nfctCb = nfct_new();
    if(!nfqres->nfctCb) GOTO_ERROR(err, "new nf conntrack cb failed");
    nfqres->nfctCbHd = nfct_open();
    if(!nfqres->nfctCbHd) GOTO_ERROR(err, "open nf conntrack cb failed");
    //register
    nfct_callback_register((struct nfct_handle *)nfqres->nfctHd, NFCT_T_ALL, UpdateNetSession, nfqres);
    /*return*/
    return 0;
err:
    if(nfqres->nfct) nfct_destroy((NF_CONNTRACK *)nfqres->nfct);
    if(nfqres->nfctCb) nfct_destroy((NF_CONNTRACK *)nfqres->nfctCb);
    if(nfqres->nfctHd) nfct_close((struct nfct_handle *)nfqres->nfctHd);
    if(nfqres->nfctCbHd) nfct_close((struct nfct_handle *)nfqres->nfctCbHd);
    return -1;
}

int OpenNfque(int quenum, NFQ_RES_INFO *nfqres)
{
    int ret;
    struct nfq_handle *h = NULL;
    struct nfq_q_handle *qh = NULL;
    /*nfq open*/
    h = nfq_open();
    if(!h) RETURN_ERROR(-1, "nfq_open failed.");

    ret = nfq_unbind_pf(h, AF_INET);
    if(ret < 0) GOTO_ERROR(err, "nfq unbind pf failed.");

    ret = nfq_bind_pf(h, AF_INET);
    if(ret < 0) GOTO_ERROR(err, "fq bind pf failed.");

    if(quenum == DIR_INGRESS) {
        qh = nfq_create_queue(h, quenum, &input_nfq_cb, (void *)nfqres);
    } else {
        qh = nfq_create_queue(h, quenum, &output_nfq_cb, (void *)nfqres);
    }
    if(!qh) GOTO_ERROR(err, "nfq create queue failed");

    ret = nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xff);
    if(ret < 0) GOTO_ERROR(err, "nfq set mode failed.");

    /*save nfqueue handle*/
    if(quenum == DIR_INGRESS) {
        nfqres->inputFd = nfq_fd(h);
        nfqres->inputQue = (void *)qh;
    } else {
        nfqres->outputFd = nfq_fd(h);
        nfqres->outputQue = (void *)qh;
    }
    /*return*/
    return 0;

err:
    if(h) nfq_close(h);
    if(qh) nfq_destroy_queue(qh);
    /*return*/
    return -1;
}

int NfqueueRcvData(int32_t zRcvEvFd, int32_t fd, void *ptr)
{
    int ret;
    char buf[10240];
    NFQ_RES_INFO *nfqRes = NULL;
    struct nfq_q_handle *qh;
    RCV_EPOLL_CB *nfqEvent = (RCV_EPOLL_CB *)ptr;
    if(!ptr) RETURN_ERROR(0, "the argument pointer is nil.");
    nfqRes = &nfqEvent->nfqres;
    /*read data*/
    ret = read(fd, buf, sizeof(buf));
    if(ret <= 0)
    {
        if((errno == 0) || (errno == EAGAIN) || (errno == EINTR)) RETURN_WARN(0, "read data failed, fd : %d, %s.", fd, strerror(errno));
        close(fd);
        RETURN_ERROR(0, "read nfqueue data failed, ret : %d, fd : %d, pid : %d, %s.", ret, fd, nfqRes->pid, strerror(errno));
    }
    /*check buffer*/
    if(ret == (int)sizeof(buf)) RETURN_ERROR(0, "read nfqueue data is overflow.");
    /*get nfq handle*/
    qh = (struct nfq_q_handle *)nfqRes->inputQue;
    if(fd != nfqRes->inputFd) qh = (struct nfq_q_handle *)nfqRes->outputQue;
    /*parse nfqueue data*/
    nfq_handle_packet(qh->h, buf, ret);
    /*return*/
    return 0;
}

int AddEpollEvent(int zEvfd, NFQ_RES_INFO *nfqres)
{
    int ret;
    struct epoll_event ev;
    RCV_EPOLL_CB *nfqInput = new RCV_EPOLL_CB;
    RCV_EPOLL_CB *nfqOutput = new RCV_EPOLL_CB;
    if(!nfqInput || !nfqOutput) RETURN_ERROR(-1, "new nfqueue resource info memory failed, %s.", strerror(errno));
    /*copy data*/
    memcpy(&nfqInput->nfqres, nfqres, sizeof(NFQ_RES_INFO));
    memcpy(&nfqOutput->nfqres, nfqres, sizeof(NFQ_RES_INFO));
    /*set nonblock*/
    fcntl(nfqres->inputFd, F_SETFL, fcntl(nfqres->inputFd, F_GETFL) | O_NONBLOCK);
    fcntl(nfqres->outputFd, F_SETFL, fcntl(nfqres->outputFd, F_GETFL) | O_NONBLOCK);
    /*input queue event*/
    nfqInput->fd = nfqres->inputFd;
    nfqInput->epollinfunc = NfqueueRcvData;
    //register epoll event
    ev.data.ptr = nfqInput;
    ev.events = EPOLLIN;
    ret = epoll_ctl(zEvfd, EPOLL_CTL_ADD, nfqres->inputFd, &ev);
    if(ret < 0) RETURN_ERROR(-2, "add nfqueue handle to epoll failed, pid : %d, %s.", nfqres->inputFd, strerror(errno));
    /*output queue event*/
    nfqOutput->fd = nfqres->outputFd;
    nfqOutput->epollinfunc = NfqueueRcvData;
    //register epoll event
    ev.data.ptr = nfqOutput;
    ev.events = EPOLLIN;
    ret = epoll_ctl(zEvfd, EPOLL_CTL_ADD, nfqres->outputFd, &ev);
    if(ret < 0) RETURN_ERROR(-2, "add nfqueue handle to epoll failed, pid : %d, %s.", nfqres->outputFd, strerror(errno));
    /*print debug log*/
    LOG_D("pid : %d, inputfd : %d, outputfd : %d.", nfqres->pid, nfqres->inputFd, nfqres->outputFd);
    nfqres->inputCb = nfqInput;
    nfqres->outputcb = nfqOutput;
    /*return*/
    return 0;
}

int InitNfqueue(int zRcvEvFd, NET_CTRL_INFO &ctrl)
{
    int ret;
    NFQ_RES_INFO *nfqres = NULL;
    //check resource
    auto it = NfqueResData.find(ctrl.podId);
    if(it != NfqueResData.end()) RETURN_WARN(0, "repeate pod resource, pid : %d.", ctrl.pid);
    //new memory
    nfqres = new NFQ_RES_INFO;
    if(!nfqres) RETURN_ERROR(-3, "new nfq resource info failed, %s.", strerror(errno));
    /*save pid*/
    nfqres->pid = ctrl.pid;
    nfqres->podId = ctrl.podId;
    /*init input queue*/
    ret = OpenNfque(DIR_INGRESS, nfqres);
    if(ret != 0) GOTO_ERROR(err, "init input queue resource failed, pid : %d.", ctrl.pid);
    /*init output queue*/
    ret = OpenNfque(DIR_EGRESS, nfqres);
    if(ret != 0) GOTO_ERROR(err, "init output queue resource failed, pid : %d.", ctrl.pid);
    /*init conntrack*/
    ret = OpenConntrack(nfqres);
    if(ret != 0) GOTO_ERROR(err, "init conntrack resource failed, pid : %d.", ctrl.pid);
    /*add epoll event*/
    ret = AddEpollEvent(zRcvEvFd, nfqres);
    if(ret < 0) GOTO_ERROR(err, "add %d epoll event failed.", ctrl.pid);
    /*save nfqueue resource*/
    NfqueResData.insert(pair<uint64_t, NFQ_RES_INFO *>(ctrl.podId, nfqres));
    /*return*/
    return 0;

err:
    DestroyNfqueResource(nfqres);
    /*return*/
    return -1;
}

/*nfqueue release*/
int ReleaseNfqueResource(int podId)
{
    /*find nfqueue resource infor*/
    auto it = NfqueResData.find(podId);
    if(it == NfqueResData.end()) return 0;
    /*release resource*/
    DestroyNfqueResource(it->second);
    /*return*/
    return 0;
}

int ClearSetData()
{
    MaskCidr.clear();
    Priority.clear();
    MaskCidr.insert(32);
    return 0;
}

/*delete policy*/
int DeletePolicy(NET_CTRL_INFO &ctrl)
{
    string key;
    FLOW_DIR value;
    map<string, FLOW_DIR>* subPolicy;
    map<string, map<string, FLOW_DIR>*>::iterator keyIt;
    //clear
    if(NetPolicyKey.size() == 0) return ClearSetData();
    //find
    keyIt = NetPolicyKey.find(ctrl.policyKey);
    if(keyIt == NetPolicyKey.end()) return 0;
    //get value
    subPolicy = keyIt->second;
    NetPolicyKey.erase(keyIt);
    //print debug log
    LOG_D("sub policy numbers : %lu.", subPolicy->size());
    //clear
    if(NetPolicyKey.size() == 0) ClearSetData();
    //
    for(auto it = subPolicy->begin(); it != subPolicy->end(); it++)
    {
        key = it->first;
        value = it->second;
        //print debug log
        LOG_V("flow dir : %s, key : %s.", (value == DIR_INGRESS) ? "ingress" : "egress", key.c_str());
        //
        switch (value)
        {
            case DIR_INGRESS:
                NetInputPolicyRule.erase(key);
                break;
            case DIR_EGRESS:
                NetOutputPolicyRule.erase(key);
                break;
            default:
                break;
        }
    }
    subPolicy->clear();
    delete subPolicy;
    /*print debug log*/
    LOG_D("delete net policy rule, key : %s", ctrl.policyKey.c_str());
    return 0;
}

/*add policy*/
int AddNewPolicy(RULE_DETAIL &policy, RULE_PORT &stPort)
{
    string key;
    map<string, FLOW_DIR>* subPolicy;
    map<string, FLOW_DIR>::iterator it;
    map<string, RULE_DETAIL> *ruleQue;
    map<string, RULE_DETAIL>::iterator ruleIt;
    map<string, map<string, FLOW_DIR>*>::iterator keyIt;
    //check
    if((policy.priority <= 0) || (policy.priority >= 129)) RETURN_ERROR(-1, "priority is error, need 0 < priority < 129, priority : %d", policy.priority);
    //print debug log
    PrintPolicyData(policy, stPort);
    //find
    keyIt = NetPolicyKey.find(policy.policyKey);
    if(keyIt == NetPolicyKey.end())
    {
        subPolicy = new map<string, FLOW_DIR>;
        NetPolicyKey.insert(pair<string, map<string, FLOW_DIR>*>(policy.policyKey, subPolicy));
        //print debug log
        LOG_D("create new policy : %s", policy.policyKey.c_str());
    }
    else
    {
        subPolicy = keyIt->second;
    }
    /*clear ports*/
    policy.vPorts.clear();
    //create policy rule key
    key = CreatePolicyRuleKey(policy);
    ruleQue = (policy.direction == DIR_INGRESS) ? &NetInputPolicyRule : &NetOutputPolicyRule;
    /*check key*/
    ruleIt = ruleQue->find(key);
    if(ruleIt == ruleQue->end())
    {
        policy.vPorts.push_back(stPort);
        ruleQue->insert(pair<string, RULE_DETAIL>(key, policy));
    }
    else
    {
        auto value = ruleIt->second;
        value.vPorts.push_back(stPort);
        /*delete source key*/
        ruleQue->erase(ruleIt);
        /*insert key*/
        ruleQue->insert(pair<string, RULE_DETAIL>(key, value));
        /*print debug log*/
        LOG_D("key : %s, mutil port : %d ~ %d, num : %d", key.c_str(), stPort.port, stPort.endPort, (int)value.vPorts.size());
    }
    /*insert key*/
    subPolicy->insert(pair<string, FLOW_DIR>(key, policy.direction));
    //return
    return 0;
}

/*update iptable rule*/
void UpdateMark(map<uint64_t, string> &cgRes)
{
    int mark = NET_DENY;
    FIVE_TUPLE tuple = {};
    for(auto it = cgRes.begin(); it != cgRes.end(); it++)
    {
        auto item = NfqueResData.find(it->first);
        if(item == NfqueResData.end()) CONTINUE_ERROR("can not find pod resource, pod id : %lu.", it->first);
        //set mark
        SetAcceptMark(item->second, tuple, NFCT_T_ALL, mark);
        //
        LOG_D("update mark, mark : %d, address : %s.", mark, it->second.c_str());
    }
}

/*check iptables rule*/
bool CheckIptablesRule()
{
    int length;
    FILE *fp = NULL;
    char buf[1024];
    const char *icheck  = "iptables -t mangle -S | grep TS_ZERO_PREROUTING";
    //
    fp = popen(icheck, "r");
    if(!fp) RETURN_ERROR(false, "popen iptables input command failed, %s.", strerror(errno));
    
    length = fread(buf, 1, sizeof(buf), fp);
    pclose(fp);
    
    if(length < 0) RETURN_ERROR(false, "fread iptables input command ret failed, %s.", strerror(errno));
    if((length == 0) || (strlen(buf) == 0)) return false;
    
    return true;
}

/*exec iptables*/
void WriteIptableRule(int iMarkNum, int oMarkNum)
{
    int ret;
    FILE *fp = NULL;
    char buf[1024];
    char cmd[1024];
    const char *pcheck  = "iptables -t mangle -S | grep TS_ZERO_PREROUTING";
    const char *ocheck  = "iptables -t mangle -S | grep TS_ZERO_OUTPUT";

    const char *icreate = "iptables -t mangle -N TS_ZERO_PREROUTING 2>/dev/null && iptables -t mangle -I PREROUTING -j TS_ZERO_PREROUTING";
    const char *ocreate = "iptables -t mangle -N TS_ZERO_OUTPUT 2>/dev/null && iptables -t mangle -I OUTPUT -j TS_ZERO_OUTPUT";

    const char *imark  = "iptables -t mangle -I PREROUTING -j CONNMARK --restore-mark";
    const char *omark  = "iptables -t mangle -I OUTPUT -j CONNMARK --restore-mark";

    const char *simark = "iptables -t mangle -A INPUT -j CONNMARK --save-mark";
    const char *somark = "iptables -t mangle -A POSTROUTING -j CONNMARK --save-mark";

    const char *ipass  = "iptables -t mangle -A TS_ZERO_PREROUTING -m mark --mark %d -j ACCEPT";
    const char *infque = "iptables -t mangle -A TS_ZERO_PREROUTING -j NFQUEUE --queue-num 0 --queue-bypass";
    
    const char *opass  = "iptables -t mangle -A TS_ZERO_OUTPUT -m mark --mark %d -j ACCEPT";
    const char *onfque = "iptables -t mangle -A TS_ZERO_OUTPUT -j NFQUEUE --queue-num 1 --queue-bypass";
    //
    const char *clear  = "iptables -t mangle -F";
    const char *dichan = "iptables -t mangle -X TS_ZERO_PREROUTING";
    const char *dochan = "iptables -t mangle -X TS_ZERO_OUTPUT";
    //check iptables rule
    //if(CheckIptablesRule()) return;
    if(CheckIptablesRule()) {
        system(clear);
        system(dichan);
        system(dochan);
    }
    //
    fp = popen(pcheck, "r");
    if(!fp) GOTO_ERROR(err, "popen iptables input command failed, %s.", strerror(errno));
    ret = fread(buf, 1, sizeof(buf), fp);
    if(ret < 0) GOTO_ERROR(err, "fread iptables input command ret failed, %s.", strerror(errno));
    if((ret == 0) || (strlen(buf) == 0))
    {
        system(icreate);
        system(imark);
        bzero(cmd, sizeof(cmd));
        sprintf(cmd, ipass, iMarkNum);
        system(cmd);
        system(infque);
        system(simark);
    }
    pclose(fp);
    //
    fp = popen(ocheck, "r");
    if(!fp) GOTO_ERROR(err, "popen iptables output command failed, %s.", strerror(errno));
    ret = fread(buf, 1, sizeof(buf), fp);
    if(ret < 0) GOTO_ERROR(err, "fread iptables output command ret failed, %s.", strerror(errno));
    if((ret == 0) || (strlen(buf) == 0))
    {
        system(ocreate);
        system(omark);
        bzero(cmd, sizeof(cmd));
        sprintf(cmd, opass, oMarkNum);
        system(cmd);
        system(onfque);
        system(somark);
    }
    pclose(fp);
    return;
err:
    if(fp) pclose(fp);
    return;
}

int ParseNetPolicy(char *buf)
{
    uint64_t podId;
    int i, size, num, ret;
    cJSON *root = NULL, *item, *array, *ipaddr, *ports, *rules, *param;
    std::string key, action, dir, value;
    std::vector<RULE_PORT> rulePorts = {};
    std::vector<std::string> srcip = {}, dstip = {};
    RULE_PORT rulePort = {};
    RULE_DETAIL rule = {};
    NET_CTRL_INFO ctrl = {};
    map<uint64_t, string> cgRes = {};
    /*check argument*/
    if(!buf) return -1;
    //ctrl json
    root = cJSON_Parse(buf);
    if(!root) GOTO_ERROR(err, "parse net policy json failed! original data : %s.", buf);
    //get resource key
    item = cJSON_GetObjectItem(root, "policy_name");
    if(!item) GOTO_ERROR(err, "get net policy name failed.");
    /*clear vector ports*/
    rule.vPorts.clear();
    rule.policyKey = item->valuestring;
    ctrl.policyKey = rule.policyKey;
    //clear old policy
    DeletePolicy(ctrl);
    //create new policy
    rules = cJSON_GetObjectItem(root, "rules");
    if(!rules) GOTO_ERROR(err, "get rules information failed.");

    size = cJSON_GetArraySize(rules);
    for(i = 0; i < size; i++)
    {
        array = cJSON_GetArrayItem(rules, i);
        if(!array) break;
        //action
        item = cJSON_GetObjectItem(array, "action");
        if(!item) BREAK_ERROR("get rule's action failed");
        action = item->valuestring;
        rule.action =(action.compare("Allow") == 0) ? NET_ALLOW : NET_DENY;
        //direction
        item = cJSON_GetObjectItem(array, "direction");
        if(!item) BREAK_ERROR("get rule's direction failed");
        dir = item->valuestring;
        rule.direction = (dir.compare("ingress") == 0) ? DIR_INGRESS : DIR_EGRESS;
        //source address
        ipaddr = cJSON_GetObjectItem(array, "fromAddress");
        if(!ipaddr) BREAK_ERROR("get rule's fromAddress failed");
        num = cJSON_GetArraySize(ipaddr);
        for(int j = 0; j < num; j++)
        {
            item = cJSON_GetArrayItem(ipaddr, j);
            if(!item) BREAK_ERROR("get source address info failed.");
            param = cJSON_GetObjectItem(item, "ip");
            if(!param) BREAK_ERROR("get source ip address failed.");
            value = cJSON_GetStringValue(param);
            //save source ip address
            srcip.push_back(value);
            //
            if(rule.direction != DIR_EGRESS) continue;
            param = cJSON_GetObjectItem(item, "pod_id");
            if(!param) CONTINUE_ERROR("get pod id failed.");
            podId = (uint64_t)param->valuedouble;
            cgRes.insert(pair<uint64_t, string>(podId, value));
        }
        //
        ports = cJSON_GetObjectItem(array, "ports");
        if(ports)
        {
            num = cJSON_GetArraySize(ports);
            for(int j = 0; j < num; j++)
            {
                rulePort = {};
                param = cJSON_GetArrayItem(ports, j);
                if(!param) BREAK_ERROR("get port information failed.");
                //
                item = cJSON_GetObjectItem(param, "endPort");
                if(item) rulePort.endPort = item->valueint;
                //
                item = cJSON_GetObjectItem(param, "port");
                if(item) rulePort.port = item->valueint;
                //
                item = cJSON_GetObjectItem(param, "protocol");
                if(item)
                {
                    value = item->valuestring;
                    rulePort.proto = (value.compare("TCP") == 0) ? IPPROTO_TCP : IPPROTO_UDP;
                }
                rulePort.endPort = (rulePort.endPort == 0) ? rulePort.port : rulePort.endPort;
                //push
                rulePorts.push_back(rulePort);
            }
        }
        //
        item = cJSON_GetObjectItem(array, "priority");
        if(!item) BREAK_ERROR("get rule's priority failed");
        rule.priority = item->valueint;
        //destination address
        ipaddr = cJSON_GetObjectItem(array, "toAddresses");
        if(!ipaddr) BREAK_ERROR("get rule's toAddresses failed");
        num = cJSON_GetArraySize(ipaddr);
        for(int j = 0; j < num; j++)
        {
            item = cJSON_GetArrayItem(ipaddr, j);
            if(!item) BREAK_ERROR("get destination ip address failed.");

            param = cJSON_GetObjectItem(item, "ip");
            if(!param) BREAK_ERROR("get source ip address failed.");
            value = cJSON_GetStringValue(param);
            //save source ip address
            dstip.push_back(value);
            //
            if(rule.direction != DIR_INGRESS) continue;
            param = cJSON_GetObjectItem(item, "pod_id");
            if(!param) CONTINUE_ERROR("get pod id failed.");
            podId = (uint64_t)param->valuedouble;
            cgRes.insert(pair<uint64_t, string>(podId, value));
        }
        //create network policy rule
        for(int j = 0; j < (int)srcip.size(); j++)
        {
            rule.srcIp = srcip.at(j);
            for(int n = 0; n < (int)dstip.size(); n++)
            {
                rule.dstIp = dstip.at(n);
                if(rulePorts.size() == 0)
                {
                    RULE_PORT rPort = {};
                    /*protocol*/
                    rule.proto = rPort.proto;
                    //add new policy
                    ret = AddNewPolicy(rule, rPort);
                    if(ret != 0) LOG_E("create new policy failed.");
                }
                else
                {
                    for(int p = 0; p < (int)rulePorts.size(); p++)
                    {
                        /*protocol*/
                        rule.proto = rulePorts.at(p).proto;
                        //add new policy
                        ret = AddNewPolicy(rule, rulePorts.at(p));
                        if(ret != 0) LOG_E("create new policy failed.");
                    }
                }
            }
        }
        //clear data
        rulePorts.clear();
        srcip.clear();
        dstip.clear();
    }
    //free resource
    cJSON_Delete(root);
    //update iptables rule
    UpdateMark(cgRes);
    //return
    return 0;

err:
    if(root) cJSON_Delete(root);
    return -1;
}

int ParseRcvJson(char *buf, NET_CTRL_INFO *ctrl)
{
    cJSON *root = NULL, *item;
    if(!ctrl || !buf) return -1;
    //ctrl json
    root = cJSON_Parse(buf);
    if(!root) RETURN_ERROR(-2, "parse json failed! original data : %s.", buf);
    //get data type
    item = cJSON_GetObjectItem(root, "msg_type");
    if(!item) GOTO_ERROR(err, "get message type item failed!");
    ctrl->msgType = (NET_DATA_TYPE)item->valueint;
    //get pid
    item = cJSON_GetObjectItem(root, "pid");
    if(item) ctrl->pid = item->valueint;
    //get pod id
    item = cJSON_GetObjectItem(root, "pod_id");
    if(item) ctrl->podId = (uint64_t)item->valuedouble;
    //get resource key
    item = cJSON_GetObjectItem(root, "policy_name");
    if(item) ctrl->policyKey = item->valuestring;
    //free resource
    cJSON_Delete(root);
    //check data
    switch (ctrl->msgType)
    {
        case POD_PID:
        case POD_DIE:
            if(ctrl->pid == 0 || ctrl->podId == 0) RETURN_ERROR(-1, "need pod pid, message type : %d.", ctrl->msgType);
            break;
        case ADD_RULE:
        case DEL_RULE:
            if(ctrl->policyKey.length() == 0) RETURN_ERROR(-1, "need policy name, message type : %d.", ctrl->msgType);
            break;
        default:
            break;
    }

    return 0;

err:
    if(root) cJSON_Delete(root);
    return -1;
}

int ParseRcvData(int32_t zRcvEvFd, int32_t fd, void *ptr)
{
    int ret = 0, length;
    char result[1024], buf[20480];
    NET_CTRL_INFO ctrl = {};
    RULE_DETAIL net = {};
    if((fd <= 0) || (!ptr)) RETURN_ERROR(-2, "[net] parse failed by argumnet is error!");
    /*read data*/
    ret = read(fd, buf, sizeof(buf));
    if(ret <= 0)
    {
        if((errno == EAGAIN) || (errno == EINTR)) RETURN_WARN(0, "read data failed, fd : %d, %s.", fd, strerror(errno));
        close(fd);
        RETURN_ERROR(-1, "read net policy data failed, fd : %d, %s.", fd, strerror(errno));
    }
    //
    buf[ret] = 0;
    if(buf[ret - 1] == '\n') buf[--ret] = 0;
    //print debug log
    LOG_D("receive data : %s", buf);
    //set 0
    memset(result, 0, sizeof(result));
    //parse json
    ret = ParseRcvJson(buf, &ctrl);
    if(ret < 0) GOTO_ERROR(rsp, "[net] parse receive json failed!");
    //condition
    switch (ctrl.msgType)
    {
         case POD_PID:
            //set ns
            ret = SetNs(ctrl.pid, (char *)BasePath);
            if(ret < 0) GOTO_ERROR(rsp, "setns to %d failed.", ctrl.pid);
            //init nfqueue
            ret = InitNfqueue(zRcvEvFd, ctrl);
            /*print error info*/
            if(ret < 0) GOTO_ERROR(rsp, "init %d nfqueue failed.", ctrl.pid);
            //write iptables rule
            WriteIptableRule(1, 1);
            /*goto*/
            goto rsp;

        case POD_DIE:
            ret = ReleaseNfqueResource(ctrl.podId);
            goto rsp;
            
        case ADD_RULE:
            ret = ParseNetPolicy(buf); 
            //print rule size
            LOG_D("NetInputPolicyRule : %d, NetOutputPolicyRule : %d", (int)NetInputPolicyRule.size(), (int)NetOutputPolicyRule.size());
            goto rsp;

        case DEL_RULE:
            ret = DeletePolicy(ctrl);
            goto rsp;

        default:
            LOG_E("data type is error, datatype : %d.", ctrl.msgType);
            break;
    }

rsp:
    //
    SetLocalNetNs(szLocalNetNsFd);
    /*response data*/
    sprintf(result, "{\"status\":%d,\"msg_type\":%d}", ret, RSP_ACK);
    //data len
    length = strlen(result);
    //print debug log
    LOG_V("rsp data : %s.", result);
    //send response data
    ret = write(fd, result, length);
    //judge response result
    if(ret != length)
    {
        LOG_E("send result failed! %s.", strerror(errno));
        if(ret <= 0) close(fd);
        return 0;
    }

    return 0;
}

int ProcAcceptEvent(int32_t zRcvEvFd, int32_t fd, void *ptr)
{
    int ret, zClientFd;
    socklen_t cliAddrLen;
    struct epoll_event ev;
    static RCV_EPOLL_CB daemonEvent;
    struct sockaddr_un cltAddr;
    //client address length
    cliAddrLen = sizeof(struct sockaddr_in);
    zClientFd = accept(fd, (struct sockaddr *)&cltAddr, &cliAddrLen);
    if(zClientFd <= 0) RETURN_ERROR(0, "accept a new client failed, %s.", strerror(errno));
    /*close old fd*/
    if(gClientFd > 0)
    {
        if(zClientFd != gClientFd) close(gClientFd);
        LOG_W("close old globe fd, old fd : %d, new fd : %d.", gClientFd, zClientFd);
    }
    /*print debug log*/
    LOG_I("accept new unix socket link, fd : %d, log level : %d", zClientFd, gzLogLevel);
    /*save fd*/
    gClientFd = zClientFd;
    //noblock
    fcntl(zClientFd, F_SETFL, fcntl(zClientFd, F_GETFL) | O_NONBLOCK);
    /*callback*/
    daemonEvent.fd = gClientFd;
    daemonEvent.epollinfunc = ParseRcvData;
    //epoll event
    ev.data.ptr = &daemonEvent;
    ev.events = EPOLLIN;
    ret = epoll_ctl(zRcvEvFd, EPOLL_CTL_ADD, zClientFd, &ev);
    if(ret < 0)
    {
        close(zClientFd);
        LOG_E("add new client to epoll failed, %s.", strerror(errno));
    }
    return 0;
}

int ProcAcceptPostLinkEvent(int32_t zRcvEvFd, int32_t fd, void *ptr)
{
    int zClientFd;
    socklen_t cliAddrLen;
    struct sockaddr_un cltAddr;
    //client address length
    cliAddrLen = sizeof(struct sockaddr_in);
    zClientFd = accept(fd, (struct sockaddr *)&cltAddr, &cliAddrLen);
    if(zClientFd <= 0) RETURN_ERROR(0, "accept a new client failed, %s.", strerror(errno));
    /*close old fd*/
    if(gPostLinkFd > 0)
    {
        if(zClientFd != gPostLinkFd) close(gPostLinkFd);
        LOG_W("close old globe post fd, old fd : %d, new fd : %d.", gPostLinkFd, zClientFd);
    }
    /*save fd*/
    gPostLinkFd = zClientFd;
    //noblock
    fcntl(zClientFd, F_SETFL, fcntl(zClientFd, F_GETFL) | O_NONBLOCK);
    //return
    return 0;
}

int CreatePostServer(int efd, RCV_EPOLL_CB *pstPostEv)
{
    int fd = 0, ret;
    struct epoll_event ev;
    struct sockaddr_un svrAddr;
    //check argument
    if((efd <= 0) || !pstPostEv) RETURN_ERROR(-5, "the argument pointer is nil");
    //create socket
    fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if(fd <= 0) RETURN_ERROR(-2, "create unix socket failed! %s.", strerror(errno));
    //noblock
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    //socket address
    svrAddr.sun_family = AF_UNIX;
    strcpy(svrAddr.sun_path, POST_NET_UNIX);
    unlink(POST_NET_UNIX);
    //bind socket address
    ret = bind(fd, (struct sockaddr *)&svrAddr, sizeof(svrAddr));
    if(ret < 0) GOTO_ERROR(err, "bind server unix socket failed, %s!", strerror(errno));
    //listen sockfd
    ret = listen(fd, 1);
    if(ret < 0) GOTO_ERROR(err, "listen the client connect request! err : %s.", strerror(errno));
    //
    pstPostEv->fd = fd;
    pstPostEv->epollinfunc = ProcAcceptPostLinkEvent;
    //register epoll event
    ev.data.ptr = pstPostEv;
    ev.events = EPOLLIN;
    ret = epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev);
    if(ret < 0) GOTO_ERROR(err, "epoll ctl failed, %s.", strerror(errno));
    //return
    return 0;
err:
    close(fd);
    return -2;
}

int main(int argc, char *argv[])
{
    char *pcLogLevel = NULL;
    struct sockaddr_un svrAddr;
    struct epoll_event ev, events[20];
    int zListenFd = 0, epfd = 0, zLinkFd;
    int ret, nfds, i;
    RCV_EPOLL_CB unixEvent, postEvent, *pstCbEv;
    //print start log
    LOG_I("policy process start......");
    /*get log level env*/
    pcLogLevel = getenv(POLICY_LOG_LEVEL);
    if(pcLogLevel) gzLogLevel = atoi(pcLogLevel);
    //open local net ns
    OpenLocalNetNs();
    /*init cidr*/
    MaskCidr.insert(32);
    //epoll fd
    epfd = epoll_create(256);
    if(epfd <= 0) GOTO_ERROR(err, "create epoll fd failed, %s.", strerror(errno));
    //create post socket server
    ret = CreatePostServer(epfd, &postEvent);
    if(ret != 0) GOTO_ERROR(err, "create post server failed.");
    //create socket
    zListenFd = socket(PF_UNIX, SOCK_STREAM, 0);
    if(zListenFd <= 0) GOTO_ERROR(err, "create unix socket failed! %s.", strerror(errno));
    //noblock
    fcntl(zListenFd, F_SETFL, fcntl(zListenFd, F_GETFL) | O_NONBLOCK);
    //socket address
    svrAddr.sun_family = AF_UNIX;
    strcpy(svrAddr.sun_path, NET_POLICY_UNIX);
    unlink(NET_POLICY_UNIX);
    //bind socket address
    ret = bind(zListenFd, (struct sockaddr *)&svrAddr, sizeof(svrAddr));
    if(ret < 0) GOTO_ERROR(err, "bind server unix socket failed, %s!", strerror(errno));
    //listen sockfd
    ret = listen(zListenFd, 1);
    if(ret < 0) GOTO_ERROR(err, "listen the client connect request! err : %s.", strerror(errno));
    //
    unixEvent.fd = zListenFd;
    unixEvent.epollinfunc = ProcAcceptEvent;
    //register epoll event
    ev.data.ptr = &unixEvent;
    ev.events = EPOLLIN;
    ret = epoll_ctl(epfd, EPOLL_CTL_ADD, zListenFd, &ev);
    if(ret < 0) GOTO_ERROR(err, "epoll ctl failed, %s.", strerror(errno));
    //accept client request
    while (1)
    {
        nfds = epoll_wait(epfd, events, 20, -1);
        for(i = 0; i < nfds; i++)
        {
            pstCbEv = (RCV_EPOLL_CB *)events[i].data.ptr;
            /*check pointer*/
            if (!pstCbEv) continue;
            /*link fd*/
            zLinkFd = pstCbEv->fd;
            if (events[i].events & EPOLLIN)
            {
                if (!pstCbEv->epollinfunc) continue;
                /*epll in callback*/
                pstCbEv->epollinfunc(epfd, zLinkFd, (void *)pstCbEv);
            }
        }
    }
    
err:
    if(zListenFd > 0) close(zListenFd);
    if(epfd > 0) close(epfd);
    return -1;
}

