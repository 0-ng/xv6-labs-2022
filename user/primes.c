#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

void go(int p[2]){
    int prime;
    close(p[1]);
    if(read(p[0],&prime,4)==0){
        close(p[0]);
        return;
    }

    printf("prime %d\n",prime);
    int num;
    if(read(p[0],&num,4)){
        int pp[2];
        pipe(pp);
        int pid=fork();
        if(pid==0){
            go(pp);
        }else{
            close(pp[0]);
            if(num%prime)write(pp[1],&num,4);
            while(read(p[0],&num,4)){
                if(num%prime)write(pp[1],&num,4);
            }
            close(p[0]);
            close(pp[1]);
            wait(0);
        }
    }
    exit(0);
}

int
main(int argc, char **argv) {
    int p[2],i;
    pipe(p);
    int pid = fork();
    if(pid==0){
        go(p);
    }else{
        close(p[0]);
        for(i=2;i<=35;i++){
            write(p[1],&i,4);
        }
        close(p[1]);
        wait(0);
    }
    exit(0);
}
