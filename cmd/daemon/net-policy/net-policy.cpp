#include <algorithm>
#include <cstddef>
#include <memory>
#include <stdio.h>
#include <stdlib.h>
#include <string_view>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h> /* for NF_ACCEPT */
#include <errno.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <set>
#include <utility>
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
#include <map>
#include <iostream>
#include <iomanip>
#include <string>
#include <sys/time.h>
#include <gflags/gflags.h>
#include "cjson.h"
#include "glog/logging.h"
#include "log.h"
#include "http/codec.h"
#include "http/connection.h"
#include "http/extension/log.h"
#include "http/filter.h"
#include "http/http_filter_factory.h"
#include "net-policy.h"
#include "net/connection_manager.h"
#include "net/ip.h"
#include "net/utility.h"
#include "waf/plugin.h"
#include "policy/engine.h"
#include "admin/profile.h"

using namespace std;


int gzLogLevel   = 0;
bool gbWafEnable = false;
bool OldMicroSegEnable = true;

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
static char cDataBuf[102400];
static std::set<int> MaskCidr;
static std::set<int> Priority;
static std::unordered_map<uint64_t, NFQ_RES_INFO *> NfqueResData;
static std::unordered_map<uint32_t, uint8_t> NodesIp;
static std::unordered_map<std::string, RULE_DETAIL> NetInputPolicyRule;
static std::unordered_map<std::string, RULE_DETAIL> NetOutputPolicyRule;
static std::unordered_map<std::string, std::unordered_map<std::string, FLOW_DIR>*> NetPolicyKey;
static std::unordered_map<std::string, std::vector<HTTP_RULE_INFO>*> NetInputHttpPolicy;
static std::unordered_map<std::string, std::vector<HTTP_RULE_INFO>*> NetOutputHttpPolicy;
static std::map<TCP_FOUR_TUPLE_V4, http::ConnectionPtr> TcpCtInput;
static std::map<TCP_FOUR_TUPLE_V4, http::ConnectionPtr> TcpCtOutput;
static net::ConnectionManager connectionManager;
static int zIptVer = 0;

int NetProtoConvert(std::string proto)
{
    if(proto.length() == 0) return 0;
    if(proto.compare("TCP") == 0) return IPPROTO_TCP;
    if(proto.compare("UDP") == 0) return IPPROTO_UDP;
    if(proto.compare("ICMP") == 0) return IPPROTO_ICMP;
    /*return*/
    return 0;
}

const char *GetProtoString(int proto)
{
    switch (proto)
    {
    case IPPROTO_TCP:
        return "TCP";
    case IPPROTO_UDP:
        return "UDP";
    case IPPROTO_ICMP:
        return "ICMP";
    default:
        break;
    }
    return "UNKNOWN";
}

int ParseIpString(std::string input, std::vector<std::string> &ret)
{
    struct in_addr addr;
    uint32_t uzIpaddr, uzMask, uzBroadcast;
    std::stringstream ss(input);
    std::string segment, value;
    /*parse string*/
    while (std::getline(ss, segment, ','))
    {
        size_t pos = segment.find('-');
        if (pos != std::string::npos)
        {
            std::string startIP = segment.substr(0, pos);
            std::string endIP = segment.substr(pos + 1);

            size_t dotCount = std::count(startIP.begin(), startIP.end(), '.');
            if (dotCount == 3)
            {
                // Assuming it's an IPv4 range
                size_t lastDot = startIP.rfind('.');
                std::string baseIP = startIP.substr(0, lastDot + 1);
                int startRange = std::stoi(startIP.substr(lastDot + 1));
                int endRange = std::stoi(endIP);

                for (int i = startRange; i <= endRange; ++i)
                {
                    ret.push_back(baseIP + std::to_string(i));
                }
            }
			continue;
        }
        pos = segment.find('/');
		if (pos != std::string::npos) {

			// Handling CIDR notation
			std::string baseIP = segment.substr(0, pos);
			int subnetMask = std::stoi(segment.substr(pos + 1));
			uzIpaddr = ntohl(inet_addr(baseIP.c_str()));
			uzMask   = ~0 << (32 - subnetMask);
			/*count network address*/
			uzIpaddr &= uzMask;
			/*count network broadcast*/
			uzBroadcast = uzIpaddr | (~uzMask);
			// Generate all IP addresses in the subnet
			for (uint32_t i = uzIpaddr; i <= uzBroadcast; ++i)
            {
				addr.s_addr = htonl(i);
				value = inet_ntoa(addr);
				ret.push_back(value);
			}
			continue;
		}	
		// If not a range or CIDR, directly push the single IP address
		ret.push_back(segment);
    }
    /*return*/
    return 0;
}

/*now system second to string*/
std::string TimeToString()
{
    std::string data;
    char value[64], buffer[128];
    struct  tm *info  = NULL;
    struct timeval tv;
    /*buffer info*/
    memset(value, 0, sizeof(value));
    memset(buffer, 0, sizeof(buffer));
    /*time format*/
    gettimeofday(&tv, NULL);
    // 将时间转换为本地时间
    info = localtime(&tv.tv_sec);
    if(!info) return data;
    // 格式化时间为字符串
    strftime(value, sizeof(value), "%Y-%m-%d %H:%M:%S", info);
    /*milliseconds*/
    snprintf(buffer, sizeof(buffer), "%s.%03ld", value, tv.tv_usec / 1000);
    /*to string*/
    data = buffer;
    /*return*/
    return data;
}

/* Checksum a block of data */
uint16_t csum(uint16_t *packet, int packlen)
{
    unsigned long sum = 0;
    while (packlen > 1)
    {
        sum += *packet++;
        packlen -= 2;
    }
    /*sum*/
    if (packlen > 0) sum += *(uint8_t *)packet;
    /* TODO: this depends on byte order */
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    /*return*/
    return (uint16_t)~sum;
}

/*tcp checksum*/
uint16_t TcpCsum(char *packet)
{
    struct iphdr *iphdr;
    struct tcphdr *tcpphdr, *ttcphdr;
    PSEUDO_HEADER *pseudo;
    uint16_t datalen;
    char buffer[2048];
    /*ip protocol header*/
    iphdr = reinterpret_cast<struct iphdr *>(packet);
    /*check protocol*/
    if (iphdr->protocol != IPPROTO_TCP) return 0;
    /*udp protocol header*/
    tcpphdr = reinterpret_cast<struct tcphdr *>(packet + iphdr->ihl * 4);
    /*buffer length*/
	datalen = ntohs(iphdr->tot_len);
	if (datalen >= sizeof(buffer)) RETURN_ERROR(0, "create tcp checksum failed, data is too long than buffer, data len : %d", datalen);
    /*init memory*/
    memset(buffer, 0, sizeof(buffer));
    /*pesudo header*/
    pseudo = (PSEUDO_HEADER *)buffer;
    pseudo->daddr = iphdr->daddr;
    pseudo->saddr = iphdr->saddr;
    pseudo->placeholder = 0;
    pseudo->protocol = iphdr->protocol;
    pseudo->length = htons(ntohs(iphdr->tot_len) - (iphdr->ihl << 2));
    /*tcp header*/
    ttcphdr = (struct tcphdr *)(buffer + sizeof(PSEUDO_HEADER));
    memcpy(ttcphdr, tcpphdr, ntohs(pseudo->length));
    ttcphdr->check = 0;
    /*checksum*/
    return csum((uint16_t *)buffer, ntohs(pseudo->length) + sizeof(PSEUDO_HEADER)); // sizeof(PSEUDO_HEADER) + sizeof(UDP_HEADER));
}

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

std::string ipv6Convert(char *ipv6)
{
    int ret;
    string sRet = "";
    unsigned char addr[INET6_ADDRSTRLEN];
    ret = inet_pton(AF_INET6, ipv6, &(addr));
    if(ret <= 0) RETURN_ERROR(sRet, "format ipv6 address failed, ipv6 : %s.", ipv6);
    sRet = (char *)addr;
    return sRet;
}

void ipv4CidrToIp(std::string cidr, std::string &ip, int &mask)
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

std::string ipv4CidrToIp(std::string ip, int mask)
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

uint32_t ipv4StringToInt(std::string ip)
{
    struct in_addr addr;
    if (inet_pton(AF_INET, ip.c_str(), &addr) == 1) {
        return addr.s_addr;
    }
    return 0;
}

static std::string CreatePolicyRuleKey(RULE_DETAIL &info)
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
    /*return*/
    return key;
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
            /*clear data*/
            dstaddr.clear();
            srcaddr.clear();
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
                    /*save key*/
                    value.push_back(buff);
                    //all protocol
                    memset(buff, 0, sizeof(buff));
                    sprintf(buff, "%d-0-%s-%s", *it, srcaddr.at(i).c_str(), dstaddr.at(j).c_str());
                    /*save key*/
                    value.push_back(buff);
                }
            }
#if !OldMicroSegEnable
            /*clear data*/
            dstaddr.clear();
            srcaddr.clear();
            /*ingress flow*/
            if(dir != DIR_INGRESS) continue;
            srcaddr.push_back("0.0.0.0");
            srcaddr.push_back(ipv4CidrToIp(tuple.dstAddr, *iter));
            dstaddr.push_back(tuple.srcAddr);
             //list priority
            for(size_t i = 0; i < srcaddr.size(); i++)
            {
                for(size_t j = 0; j < dstaddr.size(); j++)
                {
                    memset(buff, 0, sizeof(buff));
                    sprintf(buff, "%d-%d-%s-%s", *it, tuple.proto, srcaddr.at(i).c_str(), dstaddr.at(j).c_str());
                    /*save key*/
                    value.push_back(buff);
                    //all protocol
                    memset(buff, 0, sizeof(buff));
                    sprintf(buff, "%d-0-%s-%s", *it, srcaddr.at(i).c_str(), dstaddr.at(j).c_str());
                    /*save key*/
                    value.push_back(buff);
                }
            }
#endif
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
    /*return*/
    return -1;
}

/*post match message*/
static int PostMatchMsg(FIVE_TUPLE &tuple, NET_POLICY_RULE action, FLOW_DIR dir, string &sRuleKey)
{
    int ret, len;
    char *str = NULL;
    cJSON *root = NULL;
    if(gPostLinkFd <= 0) return 0;
    //create json object
    root = cJSON_CreateObject();
    if(!root) RETURN_ERROR(-1, "create json object failed.");
    cJSON_AddStringToObject(root, "type", "microseg");
    cJSON_AddNumberToObject(root, "proto", tuple.proto);
    cJSON_AddNumberToObject(root, "action", action);
    cJSON_AddNumberToObject(root, "direction", dir);
    cJSON_AddNumberToObject(root, "src_port", tuple.srcPort);
    cJSON_AddNumberToObject(root, "dst_port", tuple.dstPort);
    cJSON_AddStringToObject(root, "src_ip", tuple.srcAddr.c_str());
    cJSON_AddStringToObject(root, "dst_ip", tuple.dstAddr.c_str());
    cJSON_AddStringToObject(root, "policy_name", sRuleKey.c_str());
    str = cJSON_PrintUnformatted(root);
    if(!str) GOTO_ERROR(err, "json format failed.");
    /*print debug log*/
    if(!((tuple.proto == IPPROTO_UDP) && (tuple.dstPort == 53))) LOG_D("[post] post micro seg data : %s", str);
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

/*match http policy rule*/
static NET_POLICY_RULE MatchHttpPolicyRule(std::vector<HTTP_RULE_INFO> *httpRules, http::Header state)
{
    std::string host, method, path;
    if(httpRules == NULL) return NET_DEFAULT;
    /*check http state*/
    for(auto it = httpRules->begin(); it != httpRules->end(); it++)
    {
        host = (*it).host;
        method = (*it).method;
        path = (*it).path;
        if(!host.empty() && (host != state.host_)) continue;
        if(!method.empty() && (method != state.method_)) continue;
        if(!path.empty() && (path != state.path_)) continue;
        /*return*/
        return (*it).action;
    }
    /*return*/
    return NET_DEFAULT;
}

/*math net policy rule*/
static NET_POLICY_RULE MatchNetPolicyRule(FIVE_TUPLE &tuple, FLOW_DIR dir, string &sRuleKey)
{
    int p;
    bool bIsMatch;
    std::string key;
    char protocol = tuple.proto;
    std::vector<std::string> ruleKeys;
    std::unordered_map<std::string, RULE_DETAIL> *ruleQue;
    std::unordered_map<std::string, RULE_DETAIL>::iterator it;
    /*is node ip*/
    auto nodeIt = NodesIp.find(tuple.uzSrcAddr);
    if(nodeIt != NodesIp.end()) return NET_DEFAULT;
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
        LOG_T("%s, find rule, key : %s, dst port : %d.", (dir == DIR_INGRESS) ? "ingress" : "egress", ruleKeys[i].c_str(), tuple.dstPort);
        //find rule
        it = ruleQue->find(ruleKeys.at(i).c_str());
        if(it == ruleQue->end()) continue;
        //print debug log
        LOG_D("i : %d, match %s rule key, key : %s, tuple proto : %d, dst port : %d, vPorts size : %d, %s.", 
            i, (dir == DIR_INGRESS) ? "ingress" : "egress", ruleKeys.at(i).c_str(), tuple.proto, tuple.dstPort, (int)it->second.vPorts.size(), PrintPortsData(it->second.vPorts).c_str());
        /*match protocol*/
        if(protocol == IPPROTO_ICMP) protocol = it->second.proto;
        if(!((it->second.proto == 0) || (protocol == it->second.proto))) break;
        /*set match false*/
        bIsMatch = false;
        /*port*/
        auto rulePorts = it->second.vPorts;
        if((rulePorts.size() == 0) || (tuple.proto == IPPROTO_ICMP)) bIsMatch = true;
        /*match port*/
        for(p = 0; p < (int)rulePorts.size(); p++)
        {
            if(rulePorts.at(p).endPort == 0) {
                bIsMatch = true;
                break;
            }
            do
            {
                if(dir != DIR_INGRESS) break;
                /*check port rang*/
                if(tuple.srcPort > rulePorts.at(p).endPort) break;
                /*check min port*/
                if(tuple.srcPort < rulePorts.at(p).port) break;
                /*set match true*/
                bIsMatch = true;
            } while(0);
            /*is match port*/
            if(bIsMatch) break;
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
        LOG_D("match %s name : %s, dir : %d, action : %d, priority : %d, proto : %d, ip : %s <--> %s port : %d ~ %d\n",
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
static int parse_package(unsigned char *pkg, FIVE_TUPLE &tuple, struct tcphdr *tcphdr, int &offset)
{
    uint16_t srcPort, dstPort;
    struct iphdr  *iph;
    struct udphdr *udph;
    struct tcphdr *tcph;
    struct in_addr addr;
    /*init buffer*/
    iph = (struct iphdr *)pkg;
    addr.s_addr     = iph->saddr;
    tuple.uzSrcAddr = iph->saddr;
    tuple.srcAddr   = inet_ntoa(addr);
    addr.s_addr     = iph->daddr;
    tuple.uzDstAddr = iph->daddr;
    tuple.dstAddr   = inet_ntoa(addr);
    if(iph->version != 4) return NF_ACCEPT;
    /*ip header length*/
    offset = iph->ihl << 2;
    /*procotol*/
    switch (iph->protocol)
    {
        case IPPROTO_UDP:
            udph = (struct udphdr *)(pkg + iph->ihl * 4);
            srcPort = udph->source;
            dstPort = udph->dest;
            offset += sizeof(struct udphdr);
            break;

        case IPPROTO_TCP:
            tcph = (struct tcphdr *)(pkg + iph->ihl * 4);
            srcPort = tcph->source;
            dstPort = tcph->dest;
            offset += tcph->doff << 2;
            memcpy(tcphdr, tcph, sizeof(struct tcphdr));
            break;
            
        case IPPROTO_ICMP:
            srcPort = 0;
            dstPort = 0;
            break;

        default:
            return NF_ACCEPT;
    }
    /*five tuple*/
    tuple.proto = iph->protocol;
    tuple.srcPort = ntohs(srcPort);
    tuple.dstPort = ntohs(dstPort);
    tuple.totLen = ntohs(iph->tot_len);
    /*return*/
    return NF_MATCH_RULE;
}

/*reset tcp link*/
static int rst_tcp_link(unsigned char *pkg)
{
    int offset, datalen;
    //uint16_t check;
    struct iphdr  *iph;
    struct tcphdr *tcph;
    /*init buffer*/
    iph = (struct iphdr *)pkg;
    if(iph->version != 4) return NF_ACCEPT;
    /*procotol*/
    if(iph->protocol != IPPROTO_TCP) return NF_ACCEPT;
    /*tcp protocol*/
    tcph = (struct tcphdr *)(pkg + iph->ihl * 4);
    //check = tcph->check;
    /*modify method*/
    offset = (iph->ihl * 4) + (tcph->doff << 2);
    datalen = ntohs(iph->tot_len) - offset;
    for(auto i = offset; i < (offset + datalen); i++)
    {
        pkg[i] = 0;
        if((i - offset) > 6) break;
    }
    /*checksum*/
    tcph->check = TcpCsum((char *)pkg);
    /*print debug log*/
    //LOG_D("src check : 0x%04x, now check : 0x%04x", check & 0xffff, tcph->check & 0xffff);
    /*return*/
    return NF_ACCEPT;
}

static int input_nfq_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *argv)
{
    bool bRet = false;
    int id = 0, ret, offset;
    uint32_t mark;
    string sRuleKey;
    FIVE_TUPLE tuple;
    struct tcphdr tcphdr;
    TCP_FOUR_TUPLE_V4 ctKey;
    NET_POLICY_RULE ruleRet;
    struct nfqnl_msg_packet_hdr *ph;
    unsigned char *pkg, *value = nullptr;
    std::map<TCP_FOUR_TUPLE_V4, http::ConnectionPtr>::iterator tcpIt;
    NFQ_RES_INFO *nfqres = (NFQ_RES_INFO *)argv;
    (void)nfqres;

    ph = nfq_get_msg_packet_hdr(nfa);
    if(!ph) return 0;

    id = ntohl(ph->packet_id);
    //printf("hw_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id);

    mark = nfq_get_nfmark(nfa);
    if((mark == NET_ALLOW) || (mark == NET_ALLOW_RSP)) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

    auto dataLen = nfq_get_payload(nfa, &pkg);
    if (dataLen < 0) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    
    //printf("payload_len=%d ", ret);
    if(dataLen < (int)sizeof(struct iphdr)) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    
    ret = parse_package(pkg, tuple, &tcphdr, offset);
    if(ret != NF_MATCH_RULE) nfq_set_verdict(qh, id, ret, 0, NULL);
    /*print debug log*/
    //LOG_V("input receive %s, mark : %d, seq: %u, tot len : %d, %s:%u -> %s:%u, memory : %p ", GetProtoString(tuple.proto), mark, ntohl(tcphdr.seq), tuple.totLen, tuple.srcAddr.c_str(), tuple.srcPort, tuple.dstAddr.c_str(), tuple.dstPort, argv);
    //LOG_D("input receive data: %p", pkg);
    if(gbWafEnable && (tuple.proto == IPPROTO_TCP))
    {
        auto status = connectionManager.receive(seastar::net::packet::from_static_data((char*)pkg, dataLen));
        if (status == net::NetStatus::Drop) {
            return nfq_set_verdict2(qh, id, NF_ACCEPT, NET_ALLOW_REQ, dataLen, pkg);
        }
    }
    /*tcp four tuple*/
    ctKey.usDstPort = tuple.dstPort;
    ctKey.usSrcPort = tuple.srcPort;
    ctKey.uzDstAddr = tuple.uzDstAddr;
    ctKey.uzSrcAddr = tuple.uzSrcAddr;
    /*tcp protocol*/
    switch (tuple.proto)
    {
    case IPPROTO_TCP:
        /*query conntrack info*/
        tcpIt = TcpCtInput.find(ctKey);
        if(tcpIt == TcpCtInput.end())
        {
            /*tcp syn*/
            if(tcphdr.syn != 0) break;
            /*tcp ack*/
            if(dataLen <= offset) return nfq_set_verdict2(qh, id, NF_ACCEPT, NET_ALLOW_REQ, 0, NULL);
            /*break*/
            break;
        }
        /*tcp tuple exist*/
        bRet = true;
        /*tcp fin*/
        if((tcphdr.fin == 1) || (tcphdr.rst == 1))
        {
            TcpCtInput.erase(ctKey);
            /*print debug log*/
            LOG_D("microseg-dp input data, delete conntrack info, src: %s:%d, dest : %s:%d", tuple.srcAddr.c_str(), tuple.srcPort, tuple.dstAddr.c_str(), tuple.dstPort);
            /*return*/
            return nfq_set_verdict2(qh, id, NF_ACCEPT, NET_ALLOW, 0, NULL);
        }
        /*tcp ack*/
        if(dataLen <= offset) return nfq_set_verdict2(qh, id, NF_ACCEPT, NET_ALLOW_REQ, 0, NULL);
        /*break*/
        break;
    case IPPROTO_UDP:
    case IPPROTO_ICMP:
        break;
    default:
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
    /*query tcp conntrack result*/
    if(!bRet)
    {
        /*match rule*/
        ruleRet = MatchNetPolicyRule(tuple, DIR_INGRESS, sRuleKey);
        if(ruleRet == NET_DEFAULT) return nfq_set_verdict2(qh, id, NF_ACCEPT, NET_ALLOW, 0, NULL);
        /*query http rule*/
        auto httpRule = NetInputHttpPolicy.find(sRuleKey);
        /*check http rule*/
        if((httpRule == NetInputHttpPolicy.end()) || (tuple.proto == IPPROTO_UDP) || (tuple.proto == IPPROTO_ICMP) || (httpRule->second->size() == 0))
        {
            /*post match message*/
            PostMatchMsg(tuple, ruleRet, DIR_INGRESS, sRuleKey);
            //deny
            if(ruleRet == NET_DENY)
            {
                LOG_D("input drop %s %s:%u -> %s:%u ", GetProtoString(tuple.proto), tuple.srcAddr.c_str(), tuple.srcPort, tuple.dstAddr.c_str(), tuple.dstPort);
                /*drop data*/
                return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
            }
            /*return*/
            return nfq_set_verdict2(qh, id, NF_ACCEPT, NET_ALLOW, 0, NULL);
        }
    }

    auto tcpSeq = ntohl(tcphdr.seq);
    /*tcp syn packet*/
    if(tcphdr.syn == 1)
    {
        LOG_D("microseg-dp  input sync, src: %s, dest : %s, offset : %d, data len : %d", tuple.srcAddr.c_str(),  tuple.dstAddr.c_str(), offset, dataLen);
        auto conn  = std::make_unique<http::Connection>(sRuleKey);
        conn->setTcpSeq(tcpSeq + 1);
        TcpCtInput.insert({ctKey, std::move(conn)});
        /*return*/
        return nfq_set_verdict2(qh, id, NF_ACCEPT, NET_ALLOW_REQ, 0, NULL);
    }
    /*print debug log*/
    LOG_D("microseg-dp  input data, src: %s, dest : %s, offset : %d, data len : %d", tuple.srcAddr.c_str(),  tuple.dstAddr.c_str(), offset, dataLen);
    /*can not find tcp conntrack*/
    if(tcpIt == TcpCtInput.end())
    {
        LOG_D("microseg-dp input not sync, new conntrack, src: %s, dest : %s, offset : %d, data len : %d", tuple.srcAddr.c_str(),  tuple.dstAddr.c_str(), offset, dataLen);
        auto [it, success] = TcpCtInput.insert({ctKey, std::make_unique<http::Connection>(sRuleKey)});
        if (success) {
            tcpIt = it;
        }
    }
    /*get tcp data*/
    value = pkg + offset;
    /*get rule key*/
    sRuleKey = tcpIt->second->getRuleKey();
    /*get tcp seq*/
    if(tcpSeq < tcpIt->second->getTcpSeq()) {
        LOG_D("input - duplicated tcp segment");
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
    auto payloadLen = dataLen - offset;
    /*save tcp seq*/
    tcpIt->second->setTcpSeq(tcpSeq + payloadLen);
    /*string convert*/
    auto data = std::string_view(reinterpret_cast<const char *>(value), payloadLen);
    auto header = tcpIt->second->onData(data);
    LOG_D("input method : %s, path : %s, host : %s, state : %d", header.method_.c_str(), header.path_.c_str(), header.host_.c_str(), static_cast<int>(header.parseState_));
    /*parse http state*/
    if(header.parseState_ != ParseState::Done) return nfq_set_verdict2(qh, id, NF_ACCEPT, NET_ALLOW_REQ, 0, NULL);
    /*get rule key*/
    sRuleKey = tcpIt->second->getRuleKey();
    /*query http rule*/
    auto httpRule = NetInputHttpPolicy.find(sRuleKey);
    if(httpRule == NetInputHttpPolicy.end()) return nfq_set_verdict2(qh, id, NF_ACCEPT, NET_DEFAULT, 0, NULL);
    // process header
    ruleRet = MatchHttpPolicyRule(httpRule->second, header);
    /*print debug log*/
    LOG_D("match input http rule : %d, key : %s", ruleRet, sRuleKey.c_str());
    /*net rule continue*/
    if(ruleRet == NET_DEFAULT) return nfq_set_verdict2(qh, id, NF_ACCEPT, NET_ALLOW_REQ, 0, NULL);
    /*post match message*/
    PostMatchMsg(tuple, ruleRet, DIR_INGRESS, sRuleKey);
    /*rst tcp link*/
    if(ruleRet == NET_DENY) rst_tcp_link(pkg);
    /*send rst http*/
    return nfq_set_verdict2(qh, id, NF_ACCEPT, NET_ALLOW_REQ, dataLen, pkg);
}

static int output_nfq_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *argv)
{
    bool bRet = false;
    int id = 0, ret, offset;
    uint32_t mark;
    std::string sRuleKey;
    FIVE_TUPLE tuple;
    struct tcphdr tcphdr;
    TCP_FOUR_TUPLE_V4 ctKey;
    struct nfqnl_msg_packet_hdr *ph;
    unsigned char *pkg, *value;
    NET_POLICY_RULE ruleRet;
    std::map<TCP_FOUR_TUPLE_V4, http::ConnectionPtr>::iterator tcpIt;
    // NFQ_RES_INFO *nfqres = (NFQ_RES_INFO *)argv;
    // nfqres = nfqres;

    ph = nfq_get_msg_packet_hdr(nfa);
    if(!ph) return 0;

    id = ntohl(ph->packet_id);
    //printf("hw_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id);

    mark = nfq_get_nfmark(nfa);
    if((mark == NET_ALLOW) || (mark == NET_ALLOW_REQ)) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

    auto dataLen = nfq_get_payload(nfa, &pkg);
    if (dataLen < 0) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    
    //printf("payload_len=%d ", ret);
    if(dataLen < (int)sizeof(struct iphdr)) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    
    ret = parse_package(pkg, tuple, &tcphdr, offset);
    if(ret != NF_MATCH_RULE) nfq_set_verdict(qh, id, ret, 0, NULL);
    /*print debug log*/
    //LOG_V("output receive %s, mark : %d, seq: %u, tot len : %d, %s:%u -> %s:%u, memory : %p ", GetProtoString(tuple.proto), mark, ntohl(tcphdr.seq), tuple.totLen, tuple.srcAddr.c_str(), tuple.srcPort, tuple.dstAddr.c_str(), tuple.dstPort, argv);
    //LOG_D("input receive data: %p", pkg);
    if(gbWafEnable && (tuple.proto == IPPROTO_TCP))
    {
        auto status = connectionManager.receive(seastar::net::packet::from_static_data((char*)pkg, dataLen));
        if (status == net::NetStatus::Drop) {
            //LOG_D("drop pkt: %p", pkg);
            return nfq_set_verdict2(qh, id, NF_ACCEPT, NET_ALLOW_RSP, dataLen, pkg);
        }
    }
    /*tcp four tuple*/
    ctKey.usDstPort = tuple.dstPort;
    ctKey.usSrcPort = tuple.srcPort;
    ctKey.uzDstAddr = tuple.uzDstAddr;
    ctKey.uzSrcAddr = tuple.uzSrcAddr;
    /*tcp protocol*/
    switch (tuple.proto)
    {
    case IPPROTO_TCP:
        /*query conntrack info*/
        tcpIt = TcpCtOutput.find(ctKey);
        if(tcpIt == TcpCtOutput.end())
        {
            /*tcp syn*/
            if(tcphdr.syn != 0) break;
            /*tcp ack*/
            if(dataLen <= offset) return nfq_set_verdict2(qh, id, NF_ACCEPT, NET_ALLOW_RSP, 0, NULL);
            /*break*/
            break;
        }
        /*tcp tuple exist*/
        bRet = true;
        /*tcp fin*/
        if((tcphdr.fin == 1) || (tcphdr.rst == 1))
        {
            TcpCtOutput.erase(ctKey);
            /*print debug log*/
            LOG_D("microseg-dp out data, delete conntrack info, src: %s:%d, dest : %s:%d", tuple.srcAddr.c_str(), tuple.srcPort, tuple.dstAddr.c_str(), tuple.dstPort);
            /*return*/
            return nfq_set_verdict2(qh, id, NF_ACCEPT, NET_ALLOW, 0, NULL);
        }
        /*tcp ack*/
        if(dataLen <= offset) return nfq_set_verdict2(qh, id, NF_ACCEPT, NET_ALLOW_RSP, 0, NULL);
        /*break*/
        break;
    case IPPROTO_UDP:
    case IPPROTO_ICMP:
        break;
    default:
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
    /*query tcp conntrack result*/
    if(!bRet)
    {
        /*match rule*/
        ruleRet = MatchNetPolicyRule(tuple, DIR_EGRESS, sRuleKey);
        if(ruleRet == NET_DEFAULT) return nfq_set_verdict2(qh, id, NF_ACCEPT, NET_ALLOW, 0, NULL);
        /*query http rule*/
        auto httpRule = NetOutputHttpPolicy.find(sRuleKey);
        /*check http rule*/
        if((httpRule == NetOutputHttpPolicy.end()) || (tuple.proto == IPPROTO_UDP) || (tuple.proto == IPPROTO_ICMP) || (httpRule->second->size() == 0))
        {
            /*post match message*/
            PostMatchMsg(tuple, ruleRet, DIR_EGRESS, sRuleKey);
            //deny
            if(ruleRet == NET_DENY)
            {
                LOG_D("output drop %s %s:%u -> %s:%u ", GetProtoString(tuple.proto), tuple.srcAddr.c_str(), tuple.srcPort, tuple.dstAddr.c_str(), tuple.dstPort);
                /*drop data*/
                return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
            }
            /*return*/
            return nfq_set_verdict2(qh, id, NF_ACCEPT, NET_ALLOW, 0, NULL);
        }
    }
    auto tcpSeq = ntohl(tcphdr.seq);
    /*tcp syn packet*/
    if(tcphdr.syn == 1)
    {
        LOG_D("microseg-dp output sync, rule key : %s, src: %s, dest : %s, offset : %d, data len : %d", sRuleKey.c_str(), tuple.srcAddr.c_str(),  tuple.dstAddr.c_str(), offset, dataLen);
        auto conn  = std::make_unique<http::Connection>(sRuleKey);
        conn->setTcpSeq(tcpSeq + 1);
        TcpCtOutput.insert({ctKey, std::move(conn)});
        /*return*/
        return nfq_set_verdict2(qh, id, NF_ACCEPT, NET_ALLOW_RSP, 0, NULL);
    }
    /*print debug log*/
    LOG_D("microseg-dp output data, src: %s, dest : %s, offset : %d, data len : %d", tuple.srcAddr.c_str(),  tuple.dstAddr.c_str(), offset, dataLen);
    /*can not find tcp conntrack*/
    if(tcpIt == TcpCtOutput.end())
    {
        LOG_D("microseg-dp output not sync, new conntrack, src: %s, dest : %s, offset : %d, data len : %d", tuple.srcAddr.c_str(),  tuple.dstAddr.c_str(), offset, dataLen);
        auto [it, success] = TcpCtOutput.insert({ctKey, std::make_unique<http::Connection>(sRuleKey)});
        if (success) {
            tcpIt = it;
        }
    }
    /*get tcp data*/
    value = pkg + offset;
    /*get rule key*/
    sRuleKey = tcpIt->second->getRuleKey();
    /*get tcp seq*/
    if(tcpSeq < tcpIt->second->getTcpSeq()) {
        LOG_D("output - duplicated tcp segment");
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }

    auto payloadLen = dataLen - offset;
    /*save tcp seq*/
    tcpIt->second->setTcpSeq(tcpSeq + payloadLen);
    /*string convert*/
    auto data = std::string_view(reinterpret_cast<const char *>(value), payloadLen);
    auto header = tcpIt->second->onData(data);
    LOG_D("output method : %s, path : %s, host : %s, state : %d, rule key : %s", header.method_.c_str(), header.path_.c_str(), header.host_.c_str(), static_cast<int>(header.parseState_), sRuleKey.c_str());
    /*parse http state*/
    if(header.parseState_ != ParseState::Done) return nfq_set_verdict2(qh, id, NF_ACCEPT, NET_ALLOW_RSP, 0, NULL);
    /*query http rule*/
    auto httpRule = NetOutputHttpPolicy.find(sRuleKey);
    if(httpRule == NetOutputHttpPolicy.end()) return nfq_set_verdict2(qh, id, NF_ACCEPT, NET_DEFAULT, 0, NULL);
    // process header
    ruleRet = MatchHttpPolicyRule(httpRule->second, header);
    /*print debug log*/
    LOG_D("match output http rule : %d, key : %s", ruleRet, sRuleKey.c_str());
    /*net rule continue*/
    if(ruleRet == NET_DEFAULT) return nfq_set_verdict2(qh, id, NF_ACCEPT, NET_ALLOW_RSP, 0, NULL);
    /*post match message*/
    PostMatchMsg(tuple, ruleRet, DIR_EGRESS, sRuleKey);
    /*rst tcp link*/
    if(ruleRet == NET_DENY) rst_tcp_link(pkg);
    /*send rst http*/
    return nfq_set_verdict2(qh, id, NF_ACCEPT, NET_ALLOW_RSP, dataLen, pkg);
}

/*destroy nfqueue resource*/
void DestroyNfqueResource(int efd, NFQ_RES_INFO *nfqres, bool isErase)
{
    struct epoll_event ev;
    struct nfq_q_handle *qh = NULL;
    if(!nfqres) return;
    /*close input fd*/
    if(nfqres->inputFd > 0)
    {
        ev.data.fd = nfqres->inputFd;
        epoll_ctl(efd, EPOLL_CTL_DEL, nfqres->inputFd, &ev);
        close(nfqres->inputFd);
    }
    /*close output fd*/
    if(nfqres->outputFd > 0)
    {
        ev.data.fd = nfqres->outputFd;
        epoll_ctl(efd, EPOLL_CTL_DEL, nfqres->outputFd, &ev);
        close(nfqres->outputFd);
    }
    /*destroy input queue*/
    if(nfqres->inputQue)
    {
        qh = (struct nfq_q_handle *)nfqres->inputQue;
        nfq_close(qh->h);
        nfq_destroy_queue(qh);
    }
    /*destroy output queue*/
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
    if(isErase) NfqueResData.erase(nfqres->podId);
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

    ret = nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff);
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
    char buf[65536];
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
    //if(ret == (int)sizeof(buf)) RETURN_ERROR(0, "read nfqueue data is overflow.");
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
    nfqres->pid    = ctrl.pid;
    nfqres->podId  = ctrl.podId;
    nfqres->pollFd = zRcvEvFd;
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
    NfqueResData.insert(make_pair(ctrl.podId, nfqres));
    /*return*/
    return 0;

err:
    DestroyNfqueResource(zRcvEvFd, nfqres, true);
    /*return*/
    return -1;
}

/*nfqueue release*/
int ReleaseNfqueResource(int efd, int podId)
{
    /*find nfqueue resource infor*/
    auto it = NfqueResData.find(podId);
    if(it == NfqueResData.end()) return 0;
    /*release resource*/
    DestroyNfqueResource(efd, it->second, true);
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
    std::unordered_map<string, FLOW_DIR>* subPolicy;
    std::unordered_map<string, std::unordered_map<string, FLOW_DIR>*>::iterator keyIt;
    /*clear input http policy*/
    auto it = NetInputHttpPolicy.find(ctrl.policyKey);
    if(it != NetInputHttpPolicy.end())
    {
        auto sit = it->second;
        delete sit;
        NetInputHttpPolicy.erase(it);
    }
    /*clear output http policy*/
    it = NetOutputHttpPolicy.find(ctrl.policyKey);
    if(it != NetOutputHttpPolicy.end())
    {
        auto sit = it->second;
        delete sit;
        NetOutputHttpPolicy.erase(it);
    }
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
#if OldMicroSegEnable
        auto value = it->second;
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
#else
        NetInputPolicyRule.erase(key);
        NetOutputPolicyRule.erase(key);
#endif
    }
    /*clear net policy*/
    subPolicy->clear();
    delete subPolicy;
    /*print debug log*/
    LOG_D("delete net policy rule, key : %s", ctrl.policyKey.c_str());
    /*return*/
    return 0;
}

int AddNewHttpPolicy(FLOW_DIR dir, std::string &key, HTTP_RULE_INFO &httpRule)
{
    std::vector<HTTP_RULE_INFO> *httpRuleArr;
    auto http = (dir == DIR_INGRESS) ? &NetInputHttpPolicy : &NetOutputHttpPolicy;
    auto it = http->find(key);
    if(it == http->end())
    {
        httpRuleArr = new std::vector<HTTP_RULE_INFO>;
        http->insert(std::make_pair(key, httpRuleArr));
        /*print debug log*/
        LOG_D("create new http policy : %s, memory address : %p.", key.c_str(), httpRuleArr);
    }
    else
    {
        httpRuleArr = it->second;
    }
    httpRuleArr->push_back(httpRule);
    /*return*/
    return 0;
}

/*add policy*/
int AddNewPolicy(RULE_DETAIL &policy, RULE_PORT &stPort)
{
    string key;
    std::unordered_map<string, FLOW_DIR>* subPolicy;
    std::unordered_map<string, FLOW_DIR>::iterator it;
    std::unordered_map<string, RULE_DETAIL> *ruleQue;
    std::unordered_map<string, RULE_DETAIL>::iterator ruleIt;
    std::unordered_map<string, std::unordered_map<string, FLOW_DIR>*>::iterator keyIt;
    //check
    if((policy.priority <= 0) || (policy.priority >= 129)) RETURN_ERROR(-1, "priority is error, need 0 < priority < 129, priority : %d", policy.priority);
    //print debug log
    PrintPolicyData(policy, stPort);
    //find
    keyIt = NetPolicyKey.find(policy.policyKey);
    if(keyIt == NetPolicyKey.end())
    {
        subPolicy = new std::unordered_map<string, FLOW_DIR>;
        NetPolicyKey.insert(make_pair(policy.policyKey, subPolicy));
        //print debug log
        LOG_D("create new policy : %s", policy.policyKey.c_str());
    }
    else
    {
        subPolicy = keyIt->second;
    }
    /*clear ports*/
    policy.vPorts.clear();
#if OldMicroSegEnable
    //create policy rule key
    key = CreatePolicyRuleKey(policy);
    ruleQue = (policy.direction == DIR_INGRESS) ? &NetInputPolicyRule : &NetOutputPolicyRule;
    /*check key*/
    ruleIt = ruleQue->find(key);
    if(ruleIt == ruleQue->end())
    {
        policy.vPorts.push_back(stPort);
        ruleQue->insert(make_pair(key, policy));
    }
    else
    {
        auto value = ruleIt->second;
        value.vPorts.push_back(stPort);
        /*delete source key*/
        ruleQue->erase(ruleIt);
        /*insert key*/
        ruleQue->insert(make_pair(key, value));
        /*print debug log*/
        LOG_D("key : %s, mutil port : %d ~ %d, num : %d", key.c_str(), stPort.port, stPort.endPort, (int)value.vPorts.size());
    }
#else
    policy.direction = DIR_INGRESS;
    key = CreatePolicyRuleKey(policy);
    ruleQue = &NetInputPolicyRule;
    /*check key*/
    ruleIt = ruleQue->find(key);
    if(ruleIt == ruleQue->end())
    {
        policy.vPorts.push_back(stPort);
        ruleQue->insert(make_pair(key, policy));
    }
    else
    {
        auto value = ruleIt->second;
        value.vPorts.push_back(stPort);
        /*delete source key*/
        ruleQue->erase(ruleIt);
        /*insert key*/
        ruleQue->insert(make_pair(key, value));
        /*print debug log*/
        LOG_D("key : %s, mutil port : %d ~ %d, num : %d", key.c_str(), stPort.port, stPort.endPort, (int)value.vPorts.size());
    }
    subPolicy->insert(make_pair(key, DIR_INGRESS));

    policy.direction = DIR_EGRESS;
    key = CreatePolicyRuleKey(policy);
    ruleQue = &NetOutputPolicyRule;
    /*check key*/
    ruleIt = ruleQue->find(key);
    if(ruleIt == ruleQue->end())
    {
        policy.vPorts.push_back(stPort);
        ruleQue->insert(make_pair(key, policy));
    }
    else
    {
        auto value = ruleIt->second;
        value.vPorts.push_back(stPort);
        /*delete source key*/
        ruleQue->erase(ruleIt);
        /*insert key*/
        ruleQue->insert(make_pair(key, value));
        /*print debug log*/
        LOG_D("key : %s, mutil port : %d ~ %d, num : %d", key.c_str(), stPort.port, stPort.endPort, (int)value.vPorts.size());
    }
#endif
    /*insert key*/
    subPolicy->insert(make_pair(key, DIR_EGRESS));
    //return
    return 0;
}

/*update iptable rule*/
void UpdateMark(std::unordered_map<uint64_t, string> &cgRes)
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
    const char *icheck  = (zIptVer == 0) ? "iptables -t mangle -S | grep TS_ZERO_PREROUTING" : "iptables-legacy -t mangle -S | grep TS_ZERO_PREROUTING";
    //
    fp = popen(icheck, "r");
    if(!fp) RETURN_ERROR(false, "popen iptables input command failed, %s.", strerror(errno));
    
    length = fread(buf, 1, sizeof(buf), fp);
    pclose(fp);
    
    if(length < 0) RETURN_ERROR(false, "fread iptables input command ret failed, %s.", strerror(errno));
    if((length == 0) || (strlen(buf) == 0)) return false;
    
    return true;
}

void ClearIptabelsRule()
{
    const char *clear  = (zIptVer == 0) ? "iptables -t mangle -F" : "iptables-legacy -t mangle -F";
    const char *dichan = (zIptVer == 0) ? "iptables -t mangle -X TS_ZERO_PREROUTING" : "iptables-legacy -t mangle -X TS_ZERO_PREROUTING";
    const char *dochan = (zIptVer == 0) ? "iptables -t mangle -X TS_ZERO_OUTPUT" : "iptables-legacy -t mangle -X TS_ZERO_OUTPUT";
    system(clear);
    system(dichan);
    system(dochan);
}

/*exec iptables*/
void WriteIptableRule(int iMarkNum, int oMarkNum)
{
    int ret;
    FILE *fp = NULL;
    char buf[1024];
    char cmd[1024];
    const char *simark = nullptr;
    const char *somark = nullptr;

    const char *pcheck  = (zIptVer == 0) ? "iptables -t mangle -S | grep TS_ZERO_PREROUTING" : "iptables-legacy -t mangle -S | grep TS_ZERO_PREROUTING";
    const char *ocheck  = (zIptVer == 0) ? "iptables -t mangle -S | grep TS_ZERO_OUTPUT" : "iptables-legacy -t mangle -S | grep TS_ZERO_OUTPUT";

    const char *icreate = (zIptVer == 0) ? "iptables -t mangle -N TS_ZERO_PREROUTING 2>/dev/null && iptables -t mangle -I PREROUTING -j TS_ZERO_PREROUTING" : "iptables-legacy -t mangle -N TS_ZERO_PREROUTING 2>/dev/null && iptables-legacy -t mangle -I PREROUTING -j TS_ZERO_PREROUTING";
    const char *ocreate = (zIptVer == 0) ? "iptables -t mangle -N TS_ZERO_OUTPUT 2>/dev/null && iptables -t mangle -I OUTPUT -j TS_ZERO_OUTPUT" : "iptables-legacy -t mangle -N TS_ZERO_OUTPUT 2>/dev/null && iptables-legacy -t mangle -I OUTPUT -j TS_ZERO_OUTPUT";

    const char *imark  = (zIptVer == 0) ? "iptables -t mangle -I PREROUTING -j CONNMARK --restore-mark" : "iptables-legacy -t mangle -I PREROUTING -j CONNMARK --restore-mark";
    const char *omark  = (zIptVer == 0) ? "iptables -t mangle -I OUTPUT -j CONNMARK --restore-mark" : "iptables-legacy -t mangle -I OUTPUT -j CONNMARK --restore-mark";

    if(!gbWafEnable)
    {
        simark = (zIptVer == 0) ? "iptables -t mangle -A INPUT -j CONNMARK --save-mark" : "iptables-legacy -t mangle -A INPUT -j CONNMARK --save-mark";
        somark = (zIptVer == 0) ? "iptables -t mangle -A POSTROUTING -j CONNMARK --save-mark" : "iptables-legacy -t mangle -A POSTROUTING -j CONNMARK --save-mark";
    }

    const char *ipass  = (zIptVer == 0) ? "iptables -t mangle -A TS_ZERO_PREROUTING -m mark --mark %d -j ACCEPT" : "iptables-legacy -t mangle -A TS_ZERO_PREROUTING -m mark --mark %d -j ACCEPT";
    const char *infque = (zIptVer == 0) ? "iptables -t mangle -A TS_ZERO_PREROUTING -j NFQUEUE --queue-num 0 --queue-bypass" : "iptables-legacy -t mangle -A TS_ZERO_PREROUTING -j NFQUEUE --queue-num 0 --queue-bypass";
    
    const char *opass  = (zIptVer == 0) ? "iptables -t mangle -A TS_ZERO_OUTPUT -m mark --mark %d -j ACCEPT" : "iptables-legacy -t mangle -A TS_ZERO_OUTPUT -m mark --mark %d -j ACCEPT";
    const char *onfque = (zIptVer == 0) ? "iptables -t mangle -A TS_ZERO_OUTPUT -j NFQUEUE --queue-num 1 --queue-bypass" : "iptables-legacy -t mangle -A TS_ZERO_OUTPUT -j NFQUEUE --queue-num 1 --queue-bypass";

    //check iptables rule
    //if(CheckIptablesRule()) return;
    if(CheckIptablesRule()) {
        ClearIptabelsRule();
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
        if(simark) system(simark);
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
        if(somark) system(somark);
    }
    pclose(fp);
    return;
err:
    if(fp) pclose(fp);
    return;
}

NET_POLICY_RULE ConvertRuleAction(std::string &str)
{
    if((str.compare("Allow") == 0) || (str.compare("Log") == 0)) return NET_ALLOW;
    if(str.compare("Alert") == 0) return NET_MARK;
    /*default*/
    return NET_DENY;
}

int ParseNodeCfg(char *buf)
{
    uint32_t uzIp;
    int i, size, action;
    std::string value, ip;
    cJSON *root = NULL, *item, *param;
    /*check argument*/
    if(!buf) return -1;
    //ctrl json
    root = cJSON_Parse(buf);
    if(!root) GOTO_ERROR(err, "parse net policy json failed! original data : %s.", buf);
    //get action
    item = cJSON_GetObjectItem(root, "action");
    if(!item) GOTO_ERROR(err, "get node action failed.");
    value = item->valuestring;
    action = (value.compare("delete") == 0) ? 0 : 1;

    //get node ips
    item = cJSON_GetObjectItem(root, "node_ips");
    if(!item) GOTO_ERROR(err, "get node ip address failed.");

    size = cJSON_GetArraySize(item);
    for(i = 0; i < size; i++)
    {
        param = cJSON_GetArrayItem(item, i);
        if(!param) break;
        //node ip
        ip = param->valuestring;
        uzIp = ipv4StringToInt(ip);
        //add or delete node ip
        if(action == 0) {
            NodesIp.erase(uzIp);
        } else {
            NodesIp[uzIp] = 1;
        }
    }
    //free resource
    cJSON_Delete(root);
    //return
    return 0;

err:
    if(root) cJSON_Delete(root);
    return -1;
}

int ParseNetPolicy(char *buf)
{
    uint64_t podId;
    int i, size, num, ret;
    cJSON *root = NULL, *item, *array, *ipaddr, *ports, *rules, *param, *httparr;
    std::string key, action, dir, value;
    std::vector<RULE_PORT> rulePorts = {};
    std::vector<std::string> srcip = {}, dstip = {};
    RULE_PORT rulePort = {};
    RULE_DETAIL rule   = {};
    NET_CTRL_INFO ctrl = {};
    HTTP_RULE_INFO http;
    std::unordered_map<uint64_t, string> cgRes = {};
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
        rule.ActionDsc = action;
        rule.action = ConvertRuleAction(rule.ActionDsc);
        //direction
#if OldMicroSegEnable
        item = cJSON_GetObjectItem(array, "direction");
        if(!item) BREAK_ERROR("get rule's direction failed");
        dir = item->valuestring;
        rule.direction = (dir.compare("ingress") == 0) ? DIR_INGRESS : DIR_EGRESS;
#endif
        //list http rule
        httparr = cJSON_GetObjectItem(array, "http");
        if(httparr)
        {
            http.action    = rule.action;
            http.direction = rule.direction;
            for(int k = 0; k < cJSON_GetArraySize(httparr); k++)
            {
                item = cJSON_GetArrayItem(httparr, k);
                if(!item) BREAK_ERROR("get http config info failed.");
                param = cJSON_GetObjectItem(item, "host");
                if(!param) BREAK_ERROR("get http host failed.");
                http.host = cJSON_GetStringValue(param);
                param = cJSON_GetObjectItem(item, "method");
                if(!param) BREAK_ERROR("get http method failed.");
                http.method = cJSON_GetStringValue(param);
                param = cJSON_GetObjectItem(item, "path");
                if(!param) BREAK_ERROR("get http path failed.");
                http.path = cJSON_GetStringValue(param);
                /*save http rule*/
                AddNewHttpPolicy(rule.direction, rule.policyKey, http);
            }
        }
        //source address
        ipaddr = cJSON_GetObjectItem(array, "fromAddress");
        if(!ipaddr) BREAK_ERROR("get rule's fromAddress failed");
        num = cJSON_GetArraySize(ipaddr);
        for(int j = 0; j < num; j++)
        {
            item = cJSON_GetArrayItem(ipaddr, j);
            if(!item) BREAK_ERROR("get source address info failed.");
            /*get ip string*/
            param = cJSON_GetObjectItem(item, "ip");
            if(!param) BREAK_ERROR("get source ip address failed.");
            value = cJSON_GetStringValue(param);
            //save source ip address
            ParseIpString(value, srcip);
            //
#if OldMicroSegEnable
            if(rule.direction != DIR_EGRESS) continue;
            param = cJSON_GetObjectItem(item, "pod_id");
            if(!param) CONTINUE_ERROR("get pod id failed.");
#else
            param = cJSON_GetObjectItem(item, "pod_id");
            if(!param) continue;
#endif
            podId = (uint64_t)param->valuedouble;
            cgRes.insert(make_pair(podId, value));
        }
        //
        ports = cJSON_GetObjectItem(array, "ports");
        if(ports)
        {
            num = cJSON_GetArraySize(ports);
            for(int j = 0; j < num; j++)
            {
                value = "";
                rulePort = {};
                //
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
                if(item) value = item->valuestring;
                //
                rulePort.proto = NetProtoConvert(value);
                //
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
            ParseIpString(value, dstip);
            //
#if OldMicroSegEnable
            if(rule.direction != DIR_INGRESS) continue;
            param = cJSON_GetObjectItem(item, "pod_id");
            if(!param) CONTINUE_ERROR("get pod id failed.");
#else
            param = cJSON_GetObjectItem(item, "pod_id");
            if(!param) continue;
#endif
            podId = (uint64_t)param->valuedouble;
            cgRes.insert(make_pair(podId, value));
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
    //get uuid
    item = cJSON_GetObjectItem(root, "uuid");
    if(item) ctrl->uuid = item->valuestring;
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

cJSON* dumpConfig() {
    cJSON * config = cJSON_CreateObject();
    // cJSON* policies = cJSON_CreateArray();
    // for_each(NetInputHttpPolicy.begin(), NetInputHttpPolicy.end() , [policies](std::vector<HTTP_RULE_INFO>* ruleVec) {
    //     cJSON* rules = cJSON_CreateArray();
    //     for_each(ruleVec->begin(), ruleVec->end(), [rules](HTTP_RULE_INFO rule) {
    //         r := cJSON_CreateObject();
            

    //     });
    //     cJSON_AddItemToArray(policies, cJSON *item)
    // } );
    cJSON* inbound_rules = cJSON_CreateArray();
    for(auto it = NetInputPolicyRule.begin(); it != NetInputPolicyRule.end(); it++) {
        auto rule = it->second;
        auto r = cJSON_CreateObject();
        cJSON* proto = cJSON_CreateNumber(rule.proto);
        cJSON_AddStringToObject(r, "policy_name", rule.policyKey.c_str());
        cJSON_AddNumberToObject(r, "priority", rule.priority);
        cJSON_AddNumberToObject(r, "direction", rule.direction);
        cJSON_AddNumberToObject(r, "action", rule.action);
        cJSON_AddItemToObject(r, "prtocol", proto);
        cJSON_AddStringToObject(r, "fromAddess", rule.srcIp.c_str());
        cJSON_AddStringToObject(r, "toAddess", rule.dstIp.c_str());
        cJSON_AddItemToArray(inbound_rules, r);
    }
    cJSON_AddItemToObject(config, "inbound_rules", inbound_rules);

    cJSON* outbound_rules = cJSON_CreateArray();
    for (auto it = NetOutputPolicyRule.begin(); it != NetOutputPolicyRule.end(); it++) {
        auto rule = it->second;
        auto r = cJSON_CreateObject();
        cJSON* proto = cJSON_CreateNumber(rule.proto);
        cJSON_AddStringToObject(r, "policy_name", rule.policyKey.c_str());
        cJSON_AddNumberToObject(r, "priority", rule.priority);
        cJSON_AddNumberToObject(r, "direction", rule.direction);
        cJSON_AddNumberToObject(r, "action", rule.action);
        cJSON_AddItemToObject(r, "prtocol", proto);
        cJSON_AddStringToObject(r, "fromAddess", rule.srcIp.c_str());
        cJSON_AddStringToObject(r, "toAddess", rule.dstIp.c_str());
        cJSON_AddItemToArray(outbound_rules, r);
    }
    cJSON_AddItemToObject(config, "outbound_rules", outbound_rules);

    cJSON* containers = cJSON_CreateArray();
    for (auto it = NfqueResData.begin(); it != NfqueResData.end(); it++) {
        auto con = it->second;
        auto item = cJSON_CreateObject();
        cJSON_AddNumberToObject(item, "pid", con->pid);
        cJSON_AddNumberToObject(item, "pod_id", con->podId);
        cJSON_AddItemToArray(containers,  item);
    }
    cJSON_AddItemToObject(config, "containers",containers);

    auto tcp = cJSON_CreateObject();
    auto stat = connectionManager.stat();
    cJSON_AddNumberToObject(tcp, "tcp_connection", stat.tcp_conn_);
    cJSON_AddItemToObject(config, "tcp",tcp);

    return config;
}

cJSON* dumpConnectons(std::string_view req) {
  cJSON* root = cJSON_Parse(req.data());
  auto limitItem = cJSON_GetObjectItem(root, "limit");
  int limit = (int)limitItem->valuedouble;

  cJSON * connections = cJSON_CreateObject();
  cJSON_AddNumberToObject(connections, "total",connectionManager.stat().tcp_conn_);
  auto items = cJSON_CreateArray();
  auto conns = connectionManager.connections();
  for (int i = 0; i < limit; i++) {
    auto item = cJSON_CreateString(conns[i].c_str());
    cJSON_AddItemToArray(items, item);
  }
  
  cJSON_AddItemToObject(connections, "items", items);
  return connections;
}

int ClearConfig(int efd)
{   
    int ret;
    /*list nfqueue resource*/
    for (auto it = NfqueResData.begin(); it != NfqueResData.end(); it++)
    {
        /*print debug log*/
        LOG_V("reset nfqueue, pid : %d.", it->second->pid);
        /*set network namespace*/
        ret = SetNs(it->second->pid, (char *)BasePath);
        if (ret != 0) continue;
        /*print debug log*/
        LOG_V("destroy nfqueue, pid : %d.", it->second->pid);
        /*clear iptables rule*/
        ClearIptabelsRule();
        /*destroy nfqueue resource*/
        DestroyNfqueResource(efd, it->second, false);
    }
    /*list policy key*/
    for(auto it = NetPolicyKey.begin(); it != NetPolicyKey.end(); it++)
    {
        it->second->clear();
    }
    /*clear policy key*/
    NetPolicyKey.clear();
    /*clear pid*/
    NfqueResData.clear();
    /*clear rule config*/
    ClearSetData();
    /*clear policy rule*/
    NetInputPolicyRule.clear();
    NetOutputPolicyRule.clear();
    /*return*/
    return 0;
}

int ParseRcvData(int32_t zRcvEvFd, int32_t fd, void *ptr)
{
    bool bRet;
    int ret = 0;
    char *result;
    NET_CTRL_INFO ctrl = {};
    RULE_DETAIL net = {};
    if((fd <= 0) || (!ptr)) RETURN_ERROR(-2, "[net] parse failed by argumnet is error!");
    /*read data*/
    ret = read(fd, cDataBuf, sizeof(cDataBuf));
    if(ret <= 0)
    {
        if((errno == EAGAIN) || (errno == EINTR)) RETURN_WARN(0, "read data failed, fd : %d, %s.", fd, strerror(errno));
        close(fd);
        RETURN_ERROR(-1, "read net policy data failed, fd : %d, %s.", fd, strerror(errno));
    }
    //
    cDataBuf[ret] = 0;
    if(cDataBuf[ret - 1] == '\n') cDataBuf[--ret] = 0;
    //print debug log
    LOG_V("receive msg, time : %s, data : %s", TimeToString().c_str(), cDataBuf);

    cJSON* respBody = nullptr;
    //parse json
    ret = ParseRcvJson(cDataBuf, &ctrl);
    if(ret < 0) GOTO_ERROR(rsp, "[net] parse receive json failed!");
    //condition
    admin::Status status;
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
            ret = ReleaseNfqueResource(zRcvEvFd, ctrl.podId);
            goto rsp;
            
        case ADD_RULE:
            ret = ParseNetPolicy(cDataBuf); 
            //print rule size
            LOG_D("NetInputPolicyRule : %d, NetOutputPolicyRule : %d", (int)NetInputPolicyRule.size(), (int)NetOutputPolicyRule.size());
            goto rsp;

        case DEL_RULE:
            ret = DeletePolicy(ctrl);
            goto rsp;

        case ADD_WAF_RULE:
            bRet = http::extension::RootContext.ParseConfiguration(cDataBuf);
            ret = (bRet == true) ? 0 : 1;
            goto rsp;
            
        case DEL_WAF_RULE:
            //delete waf config
            bRet = http::extension::RootContext.RemoveWafRule(cDataBuf);
            ret = (bRet == true) ? 0 : 1;
            goto rsp;

        case HEAP_DUMP:
            status = admin::Heap::handleHeapProfile(std::string_view{cDataBuf, strlen(cDataBuf)});
            ret = (status == admin::Status::OK) ? 0 : 1;
            goto rsp;

        case CONF_DUMP:
            respBody = dumpConfig();
            goto rsp;

        case CONN_DUMP:
            respBody = dumpConnectons(std::string_view{cDataBuf, strlen(cDataBuf)});
            goto rsp;

        case RESET:
            ret = ClearConfig(zRcvEvFd);
            goto rsp;

        case NODE_CFG:
            ret = ParseNodeCfg(cDataBuf);
            goto rsp;

        default:
            LOG_E("data type is error, datatype : %d.", ctrl.msgType);
            break;
    }

rsp:
    //
    SetLocalNetNs(szLocalNetNsFd);
    /*response data*/
    cJSON* response = cJSON_CreateObject();
    cJSON_AddNumberToObject(response, "status", ret);
    cJSON_AddNumberToObject(response, "msg_type", RSP_ACK);
    cJSON_AddStringToObject(response, "uuid", ctrl.uuid.c_str());
    if (respBody != nullptr) {
        cJSON_AddItemToObject(response, "body", respBody);
    }
    /*format reponse data*/
    if(ctrl.msgType == CONF_DUMP) {
        result = cJSON_Print(response);
    } else {
        result = cJSON_PrintUnformatted(response);
    }
    /*print response data*/
    LOG_V("rsp msg, time : %s, data : %s.", TimeToString().c_str(), result);
    //send response data
    int length = strlen(result);
    ret = write(fd, result, length);

    cJSON_Delete(response);
    if(result != NULL) free(result);

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
    http::extension::RootContext.SetPostFd(&gPostLinkFd);

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
    if(fd > 0) close(fd);
    return -2;
}

void CustomPrefix(std::ostream &s, const google::LogMessageInfo &l, void*) {
   s << std::setw(4) << 1900 + l.time.year()
   << '-'
   << setw(2) << 1 + l.time.month()
   << '-'
   << setw(2) << l.time.day()
   << 'T'
   << setw(2) << l.time.hour() << ':'
   << setw(2) << l.time.min()  << ':'
   << setw(2) << l.time.sec() << "."
   << setw(6) << l.time.usec()
   << ' '
//    << setfill(' ') << setw(5)
   << l.thread_id << setfill('0')
   << " {"
   << l.severity
   << "} "
   << l.filename << ':' << l.line_number;
}

int GetIptablesVersion()
{
    int ret;
    FILE *fp = NULL;
    std::string value;
    char buf[1024];
    /*exec command*/
    fp = popen("iptables -t nat -S PREROUTING", "r");
    if(!fp) RETURN_ERROR(-1, "popen iptables command failed, %s.", strerror(errno));
    /*init memory*/
    memset(buf, 0, sizeof(buf));
    /*read data*/
    ret = fread(buf, 1, sizeof(buf), fp);
    /*close*/
    pclose(fp);
    /*check result*/
    if(ret < 0) RETURN_ERROR(-1, "fread iptables command's ret failed, %s.", strerror(errno));
    /*to string*/
    value = buf;
    auto pos = value.find("-A PREROUTING");
    if(pos != std::string::npos) return 0;
    /*use new iptables*/
    zIptVer = 1;
    /*return*/
    return 0;
}

int main(int argc, char *argv[])
{
    google::InitGoogleLogging(argv[0], &CustomPrefix);
    google::ParseCommandLineFlags(&argc, &argv, true);
    FLAGS_logtostderr = true;

    http::HttpFilterFactory::getInstance().registerFilter( [] (size_t id, uint32_t from, uint32_t to) -> std::shared_ptr<http::HttpFilterBase> {
        return std::make_shared<http::extension::LogFilter>(id, from, to);
    });

    http::HttpFilterFactory::getInstance().registerFilter( [] (size_t id,uint32_t from, uint32_t to) -> std::shared_ptr<http::HttpFilterBase> {
        return std::make_shared<http::extension::PluginContext>(id, from, to);
    });

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
    /*get waf env*/
    pcLogLevel = getenv(POLICY_WAF_ENABLE);
    if(pcLogLevel) gbWafEnable = (strcmp(pcLogLevel, "true") == 0) ? true : false;
    //open local net ns
    OpenLocalNetNs();
    /*get iptables version*/
    GetIptablesVersion();
    /*print debug log*/
    LOG_I("choose iptables version : %d", zIptVer);
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

