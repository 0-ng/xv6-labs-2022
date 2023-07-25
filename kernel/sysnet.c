//
// network system calls.
//

#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "fs.h"
#include "sleeplock.h"
#include "file.h"
#include "net.h"

struct sock {
    struct sock *next; // the next socket in the list
    uint32 raddr;      // the remote IPv4 address
    uint16 lport;      // the local UDP port number
    uint16 rport;      // the remote UDP port number
    uint8 type;      // tcp 1; udp 2
    struct spinlock lock; // protects the rxq
    struct mbufq rxq;  // a queue of packets waiting to be received
};

static struct spinlock lock;
static struct sock *sockets;

void
sockinit(void) {
    initlock(&lock, "socktbl");
}

int
socket(struct file **f, uint8 type) {
    struct sock *si;
//
//    si = 0;
    *f = 0;
    if ((*f = filealloc()) == 0)
        goto bad;
    if ((si = (struct sock *) kalloc()) == 0)
        goto bad;
    si->type=type;
    // initialize objects
    initlock(&si->lock, "sock");
    mbufq_init(&si->rxq);
    (*f)->type = FD_SOCK;
    (*f)->readable = 1;
    (*f)->writable = 1;
    (*f)->sock = si;

    return 0;

    bad:
    if (si)
        kfree((char *) si);
    if (*f)
        fileclose(*f);
    return -1;

}

int
bind(int fd, uint32 laddr, uint16 lport) {
    struct sock *pos;
    struct proc *p = myproc();
    struct file **f = &p->ofile[fd];
    if (*f == 0)return -1;
    struct sock *si = (*f)->sock;
    si->raddr = 0xffffffff;
    si->lport = lport;
    si->rport = 0xffff;

    // add to list of sockets
    acquire(&lock);
    pos = sockets;
    while (pos) {
        if (pos->raddr == si->raddr &&
            pos->lport == si->lport &&
            pos->rport == si->rport) {
            release(&lock);
            goto bad;
        }
        pos = pos->next;
    }
    si->next = sockets;
    sockets = si;
    release(&lock);
    printf("[bind]raddr=%d, lport=%d, rport=%d\n", si->raddr, si->lport, si->rport);
    return 0;


    bad:
    if (si)
        kfree((char *) si);
    if (*f)
        fileclose(*f);
    return -1;
}


int
recvfrom(struct sock *si, uint64 addr, int n, uint64 raddr, uint64 rport) {
    struct proc *pr = myproc();
    struct mbuf *m;
    int len;

    acquire(&si->lock);
    while (mbufq_empty(&si->rxq) && !pr->killed) {
        sleep(&si->rxq, &si->lock);
    }
    if (pr->killed) {
        release(&si->lock);
        return -1;
    }
    m = mbufq_pophead(&si->rxq);
    struct server_data *server;
    server = mbufpullhdr(m, *server);
    release(&si->lock);

    len = m->len;
    if (len > n) {
        len = n;
    }
    if (copyout(pr->pagetable, addr, m->head, len) == -1) {
        mbuffree(m);
        return -1;
    }
    if (copyout(pr->pagetable, raddr, (char *) &server->raddr, sizeof(server->raddr)) == -1) {
        mbuffree(m);
        return -1;
    }
    if (copyout(pr->pagetable, rport, (char *) &server->rport, sizeof(server->rport)) == -1) {
        mbuffree(m);
        return -1;
    }
    mbuffree(m);
    return len;
}

void sendto(struct sock *si, uint64 addr, int n, uint32 raddr, uint16 rport) {
    struct proc *pr = myproc();
    struct mbuf *m;

    m = mbufalloc(MBUF_DEFAULT_HEADROOM);
    if (!m)
        return;
    printf("[sendto]send len=%d\n", n);
    if (copyin(pr->pagetable, mbufput(m, n), addr, n) == -1) {
        mbuffree(m);
        return;
    }

    switch (si->type) {
        case SOCK_DGRAM:
            net_tx_udp(m, raddr, si->lport, rport);
            break;
        case SOCK_STREAM:
            break;
        default:
            printf("[sendto]unknown type=%d\n", si->type);
    }
    return;
}

int
sockalloc(struct file **f, uint32 raddr, uint16 lport, uint16 rport) {
    struct sock *si, *pos;

    si = 0;
    *f = 0;
    if ((*f = filealloc()) == 0)
        goto bad;
    if ((si = (struct sock *) kalloc()) == 0)
        goto bad;

    // initialize objects
    si->raddr = raddr;
    si->lport = lport;
    si->rport = rport;
    initlock(&si->lock, "sock");
    mbufq_init(&si->rxq);
    (*f)->type = FD_SOCK;
    (*f)->readable = 1;
    (*f)->writable = 1;
    (*f)->sock = si;

    // add to list of sockets
    acquire(&lock);
    pos = sockets;
    while (pos) {
        if (pos->raddr == raddr &&
            pos->lport == lport &&
            pos->rport == rport) {
            release(&lock);
            goto bad;
        }
        pos = pos->next;
    }
    si->next = sockets;
    sockets = si;
    release(&lock);
    return 0;

    bad:
    if (si)
        kfree((char *) si);
    if (*f)
        fileclose(*f);
    return -1;
}

void
sockclose(struct sock *si) {
    struct sock **pos;
    struct mbuf *m;

    // remove from list of sockets
    acquire(&lock);
    pos = &sockets;
    while (*pos) {
        if (*pos == si) {
            *pos = si->next;
            break;
        }
        pos = &(*pos)->next;
    }
    release(&lock);

    // free any pending mbufs
    while (!mbufq_empty(&si->rxq)) {
        m = mbufq_pophead(&si->rxq);
        mbuffree(m);
    }

    kfree((char *) si);
}

int
sockread(struct sock *si, uint64 addr, int n) {
    struct proc *pr = myproc();
    struct mbuf *m;
    int len;

    acquire(&si->lock);
    while (mbufq_empty(&si->rxq) && !pr->killed) {
        sleep(&si->rxq, &si->lock);
    }
    if (pr->killed) {
        release(&si->lock);
        return -1;
    }
    m = mbufq_pophead(&si->rxq);
    release(&si->lock);

    len = m->len;
    if (len > n) {
        len = n;
    } else if (len == 0) {
        mbuffree(m);
        return 0;
    }
    if (copyout(pr->pagetable, addr, m->head, len) == -1) {
        mbuffree(m);
        return -1;
    }
    m->len -= len;
    acquire(&si->lock);
    mbufq_pushtail(&si->rxq, m);
    release(&si->lock);
    return len;
}

int
sockwrite(struct sock *si, uint64 addr, int n) {
    struct proc *pr = myproc();
    struct mbuf *m;

    m = mbufalloc(MBUF_DEFAULT_HEADROOM);
    if (!m)
        return -1;

    if (copyin(pr->pagetable, mbufput(m, n), addr, n) == -1) {
        mbuffree(m);
        return -1;
    }
    Dprintf("[sockwrite]raddr=%d, rport=%d, lport=%d, content=", si->raddr, si->rport, si->lport);
//    for(int i=0;i<n;i++){
//        Dprintf("%c",((char*)addr)[i]);
//    }
    Dprintf("\n");
    net_tx_udp(m, si->raddr, si->lport, si->rport);
    return n;
}

// called by protocol handler layer to deliver UDP packets
void
sockrecvudp(struct mbuf *m, uint32 raddr, uint16 lport, uint16 rport) {
    //
    // Find the socket that handles this mbuf and deliver it, waking
    // any sleeping reader. Free the mbuf if there are no sockets
    // registered to handle it.
    //
    struct sock *si;

    acquire(&lock);
    si = sockets;
    while (si) {
        if (si->raddr == raddr && si->lport == lport && si->rport == rport)
            goto found;
        if (si->raddr == 0xffffffff && si->lport == lport && si->rport == 0xffff)
            goto found_server;
        si = si->next;
    }
    release(&lock);
    mbuffree(m);
    printf("[sockrecvudp]not found, raddr=%d, lport=%d, rport=%d\n", raddr, lport, rport);
    return;

    found:
    acquire(&si->lock);
    mbufq_pushtail(&si->rxq, m);
    wakeup(&si->rxq);
    release(&si->lock);
    release(&lock);
    return;

    found_server:
    printf("[sockrecvudp]found_server\n");
    acquire(&si->lock);
    struct server_data *server;
    server = mbufpushhdr(m, *server);
    server->raddr = raddr;
    server->rport = rport;
    mbufq_pushtail(&si->rxq, m);
    wakeup(&si->rxq);
    release(&si->lock);
    release(&lock);
}
