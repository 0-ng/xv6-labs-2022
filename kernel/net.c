//
// networking protocol support (IP, UDP, ARP, etc.).
//

#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "net.h"
#include "defs.h"

static uint32 local_ip = MAKE_IP_ADDR(10, 0, 2, 15); // qemu's idea of the guest IP
static uint8 local_mac[ETHADDR_LEN] = {0x52, 0x54, 0x00, 0x12, 0x34, 0x56};
static uint8 broadcast_mac[ETHADDR_LEN] = {0xFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF};
static char icmp_type_result[132][16][256] = {
        {"回显应答(ping应答)"}, {}, {},
        {

                "网络不可达，也可能是由于网络超过了所用路由选择协议的最大距离限制而认为太远。",
                "主机不可达",
                "协议不可达，即数据报中指定的高层协议不可用",
                "端口不可达，一般指数据报要交付的应用程序未运行",
                "需要分段但DF置位致使数据报无法分段",
                "源路由失败",
                "信宿网络未知",
                "信宿主机未知",
                "源主机被隔离（已弃用）",
                "与信宿网络的通信被禁止",
                "与信宿主机的通信被禁止",
                "对特定的服务类型ToS网络不可达，由于得不到指定的服务类型而不能访问信宿网络",
                "对特定的服务类型ToS主机不可达，由于得不到指定的服务类型而不能访问信宿主机",
                "因管理者设置过滤而使主机不可达（对主机的访问被禁止）",
                "因非法的优先级而使主机不可达，所请求的优先级对该主机是不允许的",
                "因报文的优先级低于网络设置的最小优先级而使主机不可达",
        },
        {
                "源端被关闭（基本流控制）",
        },
        {
                "重定向:对网络重定向",
                "对主机重定向",
                "对服务类型和网络重定向",
                "对服务类型和主机重定向",
        }, {}, {},
        {
                "请求回显（P i n g请求）"
        },
        {
                "路由器通告"
        },
        {"路由器请求"},
        {
                "传输期间生存时间为0（Traceroute）",
                "在数据报组装期间生存时间为0"
        },
        {
                "坏的I P首部（包括各种差错）",
                "缺少必需的选项"
        },
        {
                "时间戳请求"
        },
        {
                "时间戳应答"
        },
        {
                "信息请求（作废不用）"
        },
        {
                "信息应答（作废不用）"
        },
        {
                "地址掩码请求"
        },
        {
                "地址掩码应答"
        }
};
struct arp_cache arp_cache_list[ARP_CACHE_SIZE];
struct spinlock arp_lock;

static int net_tx_arp(uint16 op, uint8 dmac[ETHADDR_LEN], uint32 dip);

// Strips data from the start of the buffer and returns a pointer to it.
// Returns 0 if less than the full requested length is available.
char *
mbufpull(struct mbuf *m, unsigned int len) {
    char *tmp = m->head;
    if (m->len < len)
        return 0;
    m->len -= len;
    m->head += len;
    return tmp;
}

// Prepends data to the beginning of the buffer and returns a pointer to it.
char *
mbufpush(struct mbuf *m, unsigned int len) {
    m->head -= len;
    if (m->head < m->buf)
        panic("mbufpush");
    m->len += len;
    return m->head;
}

// Appends data to the end of the buffer and returns a pointer to it.
char *
mbufput(struct mbuf *m, unsigned int len) {
    char *tmp = m->head + m->len;
    m->len += len;
    if (m->len > MBUF_SIZE)
        panic("mbufput");
    return tmp;
}

// Strips data from the end of the buffer and returns a pointer to it.
// Returns 0 if less than the full requested length is available.
char *
mbuftrim(struct mbuf *m, unsigned int len) {
    if (len > m->len)
        return 0;
    m->len -= len;
    return m->head + m->len;
}

// Allocates a packet buffer.
struct mbuf *
mbufalloc(unsigned int headroom) {
    struct mbuf *m;

    if (headroom > MBUF_SIZE)
        return 0;
    m = kalloc();
    if (m == 0)
        return 0;
    m->next = 0;
    m->head = (char *) m->buf + headroom;
    m->len = 0;
    memset(m->buf, 0, sizeof(m->buf));
    return m;
}

// Frees a packet buffer.
void
mbuffree(struct mbuf *m) {
    kfree(m);
}

// Pushes an mbuf to the end of the queue.
void
mbufq_pushtail(struct mbufq *q, struct mbuf *m) {
    m->next = 0;
    if (!q->head) {
        q->head = q->tail = m;
        return;
    }
    q->tail->next = m;
    q->tail = m;
}

// Pops an mbuf from the start of the queue.
struct mbuf *
mbufq_pophead(struct mbufq *q) {
    struct mbuf *head = q->head;
    if (!head)
        return 0;
    q->head = head->next;
    return head;
}

// Returns one (nonzero) if the queue is empty.
int
mbufq_empty(struct mbufq *q) {
    return q->head == 0;
}

// Intializes a queue of mbufs.
void
mbufq_init(struct mbufq *q) {
    q->head = 0;
}

// This code is lifted from FreeBSD's ping.c, and is copyright by the Regents
// of the University of California.
static unsigned short
in_cksum(const unsigned char *addr, int len) {
    int nleft = len;
    const unsigned short *w = (const unsigned short *) addr;
    unsigned int sum = 0;
    unsigned short answer = 0;

    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (nleft == 1) {
        *(unsigned char *) (&answer) = *(const unsigned char *) w;
        sum += answer;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum & 0xffff) + (sum >> 16);
    sum += (sum >> 16);
    /* guaranteed now that the lower 16 bits of sum are correct */

    answer = ~sum; /* truncate to 16 bits */
    return answer;
}

// sends an ethernet packet
static void
net_tx_eth(struct mbuf *m, uint16 ethtype, uint32 dip) {
    struct eth *ethhdr;

    ethhdr = mbufpushhdr(m, *ethhdr);
    memmove(ethhdr->shost, local_mac, ETHADDR_LEN);
    // In a real networking stack, dhost would be set to the address discovered
    // through ARP. Because we don't support enough of the ARP protocol, set it
    // to broadcast instead.
//    memmove(ethhdr->dhost, broadcast_mac, ETHADDR_LEN);
    switch (ethtype) {
        case ETHTYPE_ARP:
            memmove(ethhdr->dhost, broadcast_mac, ETHADDR_LEN);
            break;
        default:
            memmove(ethhdr->dhost, broadcast_mac, ETHADDR_LEN);
            break;
            // TODO 8.8.8.8 not work why?
            acquire(&arp_lock);
            if (!arp_cache_list[dip % ARP_CACHE_SIZE].flag) {
                if (net_tx_arp(ARP_OP_REQUEST, broadcast_mac, dip) != -1) {
                    while (!arp_cache_list[dip % ARP_CACHE_SIZE].flag) {
                        printf("wait 1\n");
                        sleep(&arp_cache_list[dip % ARP_CACHE_SIZE], &arp_lock);
                    }
                    memmove(ethhdr->dhost, arp_cache_list[dip % ARP_CACHE_SIZE].ha, ETHADDR_LEN);
                }
            } else {
                memmove(ethhdr->dhost, arp_cache_list[dip % ARP_CACHE_SIZE].ha, ETHADDR_LEN);
            }
            release(&arp_lock);
    }
    ethhdr->type = htons(ethtype);
    if (e1000_transmit(m)) {
        mbuffree(m);
    }
}

// sends an IP packet
static void
net_tx_ip(struct mbuf *m, uint8 proto, uint32 dip) {
    struct ip *iphdr;

    // push the IP header
    iphdr = mbufpushhdr(m, *iphdr);
    memset(iphdr, 0, sizeof(*iphdr));
    iphdr->ip_vhl = (4 << 4) | (20 >> 2);
    iphdr->ip_p = proto;
    iphdr->ip_src = htonl(local_ip);
    iphdr->ip_dst = htonl(dip);
    iphdr->ip_len = htons(m->len);
    iphdr->ip_ttl = 100;
//    iphdr->ip_ttl = 1;
    iphdr->ip_sum = in_cksum((unsigned char *) iphdr, sizeof(*iphdr));

    // now on to the ethernet layer
    net_tx_eth(m, ETHTYPE_IP, dip);
}

// sends a UDP packet
void
net_tx_udp(struct mbuf *m, uint32 dip,
           uint16 sport, uint16 dport) {
    struct udp *udphdr;

    // put the UDP header
    udphdr = mbufpushhdr(m, *udphdr);
    udphdr->sport = htons(sport);
    udphdr->dport = htons(dport);
    udphdr->ulen = htons(m->len);
    udphdr->sum = 0; // zero means no checksum is provided

    // now on to the IP layer
    net_tx_ip(m, IPPROTO_UDP, dip);
}

// sends an ARP packet
static int
net_tx_arp(uint16 op, uint8 dmac[ETHADDR_LEN], uint32 dip) {
    struct mbuf *m;
    struct arp *arphdr;

    m = mbufalloc(MBUF_DEFAULT_HEADROOM);
    if (!m)
        return -1;

    // generic part of ARP header
    arphdr = mbufputhdr(m, *arphdr);
    arphdr->hrd = htons(ARP_HRD_ETHER);
    arphdr->pro = htons(ETHTYPE_IP);
    arphdr->hln = ETHADDR_LEN;
    arphdr->pln = sizeof(uint32);
    arphdr->op = htons(op);

    // ethernet + IP part of ARP header
    memmove(arphdr->sha, local_mac, ETHADDR_LEN);
    arphdr->sip = htonl(local_ip);
    memmove(arphdr->tha, dmac, ETHADDR_LEN);
    arphdr->tip = htonl(dip);

    // header is ready, send the packet
    net_tx_eth(m, ETHTYPE_ARP, dip);
    return 0;
}

// receives an ARP packet
static void
net_rx_arp(struct mbuf *m) {
    struct arp *arphdr;
    uint8 smac[ETHADDR_LEN];
    uint32 sip, tip;

    arphdr = mbufpullhdr(m, *arphdr);
    if (!arphdr)
        goto done;

    // validate the ARP header
    if (ntohs(arphdr->hrd) != ARP_HRD_ETHER ||
        ntohs(arphdr->pro) != ETHTYPE_IP ||
        arphdr->hln != ETHADDR_LEN ||
        arphdr->pln != sizeof(uint32)) {
        goto done;
    }

    // only requests are supported so far
    // check if our IP was solicited
    tip = ntohl(arphdr->tip); // target IP address
//    if (ntohs(arphdr->op) != ARP_OP_REQUEST || tip != local_ip)
//        goto done;
    sip = ntohl(arphdr->sip); // sender's IP address (qemu's slirp)
    memmove(smac, arphdr->sha, ETHADDR_LEN); // sender's ethernet address
    switch (ntohs(arphdr->op)) {
        case ARP_OP_REQUEST:
            if (tip != local_ip)goto done;
            // handle the ARP request
            net_tx_arp(ARP_OP_REPLY, smac, sip);
            break;
        case ARP_OP_REPLY:
            arp_cache_list[sip % ARP_CACHE_SIZE].ip = sip;
            memmove(arp_cache_list[sip % ARP_CACHE_SIZE].ha, smac, ETHADDR_LEN);
            arp_cache_list[sip % ARP_CACHE_SIZE].flag = 1;
            acquire(&arp_lock);
            wakeup(&arp_cache_list[sip % ARP_CACHE_SIZE]);
            release(&arp_lock);
            break;
    }


    done:
    mbuffree(m);
}

// receives a UDP packet
static void
net_rx_udp(struct mbuf *m, uint16 len, struct ip *iphdr) {
    struct udp *udphdr;
    uint32 sip;
    uint16 sport, dport;


    udphdr = mbufpullhdr(m, *udphdr);
    if (!udphdr)
        goto fail;

    // TODO: validate UDP checksum

    // validate lengths reported in headers
    if (ntohs(udphdr->ulen) != len)
        goto fail;
    len -= sizeof(*udphdr);
    if (len > m->len)
        goto fail;
    // minimum packet size could be larger than the payload
    mbuftrim(m, m->len - len);

    // parse the necessary fields
    sip = ntohl(iphdr->ip_src);
    sport = ntohs(udphdr->sport);
    dport = ntohs(udphdr->dport);
    sockrecvudp(m, sip, dport, sport);
    return;

    fail:
    mbuffree(m);
}


// receives a ICMP packet
static void
net_rx_icmp(struct mbuf *m, uint16 len, struct ip *iphdr) {
    struct icmp *icmphdr;


    icmphdr = mbufpullhdr(m, *icmphdr);
    if (!icmphdr)
        goto fail;

    // validate lengths reported in headers
    len -= sizeof(*icmphdr);
    if (len > m->len)
        goto fail;
    // minimum packet size could be larger than the payload
    mbuftrim(m, m->len - len);

    // parse the necessary fields
    printf("[net_rx_icmp]%s\n", icmp_type_result[icmphdr->type][icmphdr->code]);
    return;

    fail:
    mbuffree(m);
}

// receives an IP packet
static void
net_rx_ip(struct mbuf *m) {
    struct ip *iphdr;
    uint16 len;

    iphdr = mbufpullhdr(m, *iphdr);
    if (!iphdr) {
        goto fail;
    }

    // check IP version and header len
    if (iphdr->ip_vhl != ((4 << 4) | (20 >> 2))) {
        goto fail;
    }
    // validate IP checksum
    if (in_cksum((unsigned char *) iphdr, sizeof(*iphdr))) {
        goto fail;
    }
    // can't support fragmented IP packets
    if (htons(iphdr->ip_off) != 0) {
        goto fail;
    }
    // is the packet addressed to us?
    if (htonl(iphdr->ip_dst) != local_ip)
        goto fail;
    // can only support UDP
    switch (iphdr->ip_p) {
        case IPPROTO_UDP:
            len = ntohs(iphdr->ip_len) - sizeof(*iphdr);
            net_rx_udp(m, len, iphdr);
            break;
        case IPPROTO_ICMP:
            len = ntohs(iphdr->ip_len) - sizeof(*iphdr);
            net_rx_icmp(m, len, iphdr);
            break;
        case IPPROTO_TCP:
        default:
            printf("[net_rx_ip]receive ip protocol %d\n", iphdr->ip_p);
            goto fail;
    }
    return;

    fail:
    mbuffree(m);
}

// called by e1000 driver's interrupt handler to deliver a packet to the
// networking stack
void net_rx(struct mbuf *m) {
    struct eth *ethhdr;
    uint16 type;

    ethhdr = mbufpullhdr(m, *ethhdr);
    if (!ethhdr) {
        mbuffree(m);
        return;
    }

    type = ntohs(ethhdr->type);
    if (type == ETHTYPE_IP)
        net_rx_ip(m);
    else if (type == ETHTYPE_ARP)
        net_rx_arp(m);
    else
        mbuffree(m);
}
