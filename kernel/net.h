//
// packet buffer management
//

#define MBUF_SIZE              2048
#define MBUF_DEFAULT_HEADROOM  128

struct mbuf {
    struct mbuf *next; // the next mbuf in the chain
    char *head; // the current start position of the buffer
    unsigned int len;   // the length of the buffer
    char buf[MBUF_SIZE]; // the backing store
};

char *mbufpull(struct mbuf *m, unsigned int len);

char *mbufpush(struct mbuf *m, unsigned int len);

char *mbufput(struct mbuf *m, unsigned int len);

char *mbuftrim(struct mbuf *m, unsigned int len);

// The above functions manipulate the size and position of the buffer:
//            <- push            <- trim
//             -> pull            -> put
// [-headroom-][------buffer------][-tailroom-]
// |----------------MBUF_SIZE-----------------|
//
// These marcos automatically typecast and determine the size of header structs.
// In most situations you should use these instead of the raw ops above.
#define mbufpullhdr(mbuf, hdr) (typeof(hdr)*)mbufpull(mbuf, sizeof(hdr))
#define mbufpushhdr(mbuf, hdr) (typeof(hdr)*)mbufpush(mbuf, sizeof(hdr))
#define mbufputhdr(mbuf, hdr) (typeof(hdr)*)mbufput(mbuf, sizeof(hdr))
#define mbuftrimhdr(mbuf, hdr) (typeof(hdr)*)mbuftrim(mbuf, sizeof(hdr))

struct mbuf *mbufalloc(unsigned int headroom);

void mbuffree(struct mbuf *m);

struct mbufq {
    struct mbuf *head;  // the first element in the queue
    struct mbuf *tail;  // the last element in the queue
};

void mbufq_pushtail(struct mbufq *q, struct mbuf *m);

struct mbuf *mbufq_pophead(struct mbufq *q);

int mbufq_empty(struct mbufq *q);

void mbufq_init(struct mbufq *q);


//
// endianness support
//

static inline uint16 bswaps(uint16 val) {
    return (((val & 0x00ffU) << 8) |
            ((val & 0xff00U) >> 8));
}

static inline uint32 bswapl(uint32 val) {
    return (((val & 0x000000ffUL) << 24) |
            ((val & 0x0000ff00UL) << 8) |
            ((val & 0x00ff0000UL) >> 8) |
            ((val & 0xff000000UL) >> 24));
}

// Use these macros to convert network bytes to the native byte order.
// Note that Risc-V uses little endian while network order is big endian.
#define ntohs bswaps
#define ntohl bswapl
#define htons bswaps
#define htonl bswapl


//
// useful networking headers
//

#define ETHADDR_LEN 6

// an Ethernet packet header (start of the packet).
struct eth {
    uint8 dhost[ETHADDR_LEN];
    uint8 shost[ETHADDR_LEN];
    uint16 type;
} __attribute__((packed));

#define ETHTYPE_IP  0x0800 // Internet protocol
#define ETHTYPE_ARP 0x0806 // Address resolution protocol

// an IP packet header (comes after an Ethernet header).
struct ip {
    uint8 ip_vhl; // version << 4 | header length >> 2
    uint8 ip_tos; // type of service
    uint16 ip_len; // total length
    uint16 ip_id;  // identification
    uint16 ip_off; // fragment offset field
    uint8 ip_ttl; // time to live
    uint8 ip_p;   // protocol
    uint16 ip_sum; // checksum
    uint32 ip_src, ip_dst;
};

#define IPPROTO_ICMP 1  // Control message protocol
#define IPPROTO_TCP  6  // Transmission control protocol
#define IPPROTO_UDP  17 // User datagram protocol

#define MAKE_IP_ADDR(a, b, c, d)           \
  (((uint32)a << 24) | ((uint32)b << 16) | \
   ((uint32)c << 8) | (uint32)d)


#define SOCK_STREAM 1  // tcp
#define SOCK_DGRAM 2  // udp


// a TCP packet header (comes after an IP header).
struct tcp {
    uint16 sport; // source port
    uint16 dport; // destination port
    uint32 sequence_number;  // 发送数据包中的第一个字节的序列号
    uint32 acknowledgment_number;   // 确认序列号
    uint16 alltag;
//    uint16 data_offset:4;   // 数据偏移，4位，该字段的值是TCP首部（包括选项）长度除以4
//    uint16 reserved:6;   //
//    uint16 flag:6;   // 标志位
    uint16 window;   // 表示接收缓冲区的空闲空间，16位，用来告诉TCP连接对端自己能够接收的最大数据长度。
    uint16 checksum;   // 校验和
    uint16 urgent_pointers;   // 紧急指针
    uint16 option[20];
};

#define TCP_FLAG_FIN 1<<0 //FIN表示没有数据需要发送了（在关闭TCP连接的时候使用）
#define TCP_FLAG_SYN 1<<1 //SYN表示SYN报文（在建立TCP连接的时候使用）
#define TCP_FLAG_RST 1<<2 //RST表示复位TCP连接
#define TCP_FLAG_PSH 1<<3 //PSH表示Push功能
#define TCP_FLAG_ACK 1<<4 //ACK表示Acknowledgment Number字段有意义
#define TCP_FLAG_URG 1<<5 //URG表示Urgent Pointer字段有意义


// a UDP packet header (comes after an IP header).
struct udp {
    uint16 sport; // source port
    uint16 dport; // destination port
    uint16 ulen;  // length, including udp header, not including IP header
    uint16 sum;   // checksum
};

// a ICMP packet header (comes after an IP header).
struct icmp {
    uint8 type; // 类型 type：占 1 个字节，表示较大范围类型分类的 ICMP 报文
    uint8 code; // 代码 code：占 1 个字节，表示较小范围类型分类的 ICMP 报文(type的细分)
    uint16 checksum;   // checksum
};

// an ARP packet (comes after an Ethernet header).
struct arp {
    uint16 hrd; // format of hardware address
    uint16 pro; // format of protocol address
    uint8 hln; // length of hardware address
    uint8 pln; // length of protocol address
    uint16 op;  // operation

    char sha[ETHADDR_LEN]; // sender hardware address
    uint32 sip;              // sender IP address
    char tha[ETHADDR_LEN]; // target hardware address
    uint32 tip;              // target IP address
} __attribute__((packed));


#define ARP_CACHE_SIZE  2048

struct arp_cache {
    char ha[ETHADDR_LEN]; // hardware address
    uint32 ip;// IP address
    uint8 flag;
};


#define ARP_HRD_ETHER 1 // Ethernet

enum {
    ARP_OP_REQUEST = 1, // requests hw addr given protocol addr
    ARP_OP_REPLY = 2,   // replies a hw addr given protocol addr
};

// an DNS packet (comes after an UDP header).
struct dns {
    uint16 id;  // request ID

    uint8 rd: 1;  // recursion desired
    uint8 tc: 1;  // truncated
    uint8 aa: 1;  // authoritive
    uint8 opcode: 4;
    uint8 qr: 1;  // query/response
    uint8 rcode: 4; // response code
    uint8 cd: 1;  // checking disabled
    uint8 ad: 1;  // authenticated data
    uint8 z: 1;
    uint8 ra: 1;  // recursion available

    uint16 qdcount; // number of question entries
    uint16 ancount; // number of resource records in answer section
    uint16 nscount; // number of NS resource records in authority section
    uint16 arcount; // number of resource records in additional records
} __attribute__((packed));

struct dns_question {
    uint16 qtype;
    uint16 qclass;
} __attribute__((packed));

#define ARECORD (0x0001)
#define QCLASS  (0x0001)

struct dns_data {
    uint16 type;
    uint16 class;
    uint32 ttl;
    uint16 len;
} __attribute__((packed));

struct server_data {
    uint32 raddr;
    uint16 rport;
} __attribute__((packed));

