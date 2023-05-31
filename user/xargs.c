#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"
#include "kernel/fs.h"
#include "kernel/param.h"

int
main(int argc, char *argv[]) {
    if (argc <= 1) {
        fprintf(2, "xargs error\n");
        exit(1);
    }
    char buf[128];
    int i;
    char *exec_argv[MAXARG];
    int num=0;
    for(i=1;i<argc;i++){
        exec_argv[num++]=argv[i];
    }
    int init=num;
    int m=0;
    while(read(0,buf+m,1)){
        if(buf[m]==' '){
            buf[m]='\0';
            exec_argv[num]=malloc(m+1);
            memmove(exec_argv[num++], buf, m+1);
            m=0;
        }else if(buf[m]=='\n'){
            buf[m]='\0';
            exec_argv[num]=malloc(m+1);
            memmove(exec_argv[num++], buf, m+1);
            exec_argv[num++]=0;
            if(fork()==0){
                exec(exec_argv[0], exec_argv);
                exit(1);
            }else{
                wait(0);
            }
            for(i=init;i<num-1;i++){
                free(exec_argv[i]);
            }
            m=0;
            num=init;
        }else{
            m++;
        }
    }
    exit(0);
}
