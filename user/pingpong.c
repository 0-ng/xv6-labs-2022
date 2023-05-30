#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int
main(int argc, char **argv) {
    int p[2];
    pipe(p);
    int pid = fork();
    char buf[5];
    if(pid==0){
        read(p[0], buf, sizeof buf);
        printf("%d: received %s\n",getpid(),buf);
        write(p[1],"pong",5);
        exit(0);
    }else{
        write(p[1],"ping",sizeof 5);
        wait(0);
        read(p[0], buf, sizeof buf);
        printf("%d: received %s\n",getpid(),buf);
        close(p[0]);
        close(p[1]);
    }
    exit(0);
}
