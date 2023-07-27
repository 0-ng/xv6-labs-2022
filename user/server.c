#include "kernel/types.h"
#include "kernel/net.h"
#include "kernel/stat.h"
#include "user/user.h"

//
// send a UDP packet to the localhost (outside of qemu),
// and receive a response.
//
//static void
//ping(uint16 sport, uint16 dport, int attempts) {
//    int fd;
//    char *obuf = "a message from xv6!";
//    uint32 dst;
//
//    // 10.0.2.2, which qemu remaps to the external host,
//    // i.e. the machine you're running qemu on.
//    dst = (10 << 24) | (0 << 16) | (2 << 8) | (2 << 0);
//
//    // you can send a UDP packet to any Internet address
//    // by using a different dst.
//
//    if ((fd = connect(dst, sport, dport)) < 0) {
//        fprintf(2, "ping: connect() failed\n");
//        exit(1);
//    }
//    int tmp=0;
//    for (int i = 0; i < attempts; i++) {
//        if ((tmp=write(fd, obuf, strlen(obuf))) < 0) {
//            fprintf(2, "ping: send() failed\n");
//            exit(1);
//        }
//    }
//
//    char ibuf[128];
//    int cc;
//    while((cc=read(fd, ibuf, sizeof(ibuf) - 1))!=0){
//        if (cc < 0) {
//            fprintf(2, "ping: recv() failed\n");
//            exit(1);
//        }
//        ibuf[cc]=0;
//    }
//    close(fd);
//    if (strcmp(ibuf, "this is the host!") != 0) {
//        fprintf(2, "ping didn't receive correct payload\n");
//        exit(1);
//    }
//}

//int bind(uint8 bind_port){
//    return connect(0xffffffff, bind_port, 0xffff);
//}

int
main(int argc, char *argv[]) {
//    echo "hello" | socat - udp4-datagram:localhost:26999
//    (echo "000F737D61747573" | xxd -r -p ;sleep 1)|nc -u localhost 26999|hexdump -C
    int server_fd = socket(127 << 24 | 0 << 16 | 0 << 8 | 1, 2, 0);
    int ret = bind(server_fd, 127 << 24 | 0 << 16 | 0 << 8 | 1, 2000);
    if (ret < 0) {
        printf("socket bind fail!\n");
        return -1;
    }
    uint32 raddr;
    uint16 rport;
    int cc;
    char *obuf = "a message from server!";
    char ibuf[128];
    printf("socket begin to receive\n");
    while ((cc = recvfrom(server_fd, ibuf, sizeof(ibuf) - 1, &raddr, &rport)) != 0) {
        ibuf[cc] = 0;
        printf("receive from raddr=%d, rport=%d, content=%s", raddr, rport, ibuf);
        sendto(server_fd, obuf, strlen(obuf), raddr, rport);
    }

    close(server_fd);
    exit(0);
}
