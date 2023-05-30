#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"
#include "kernel/fs.h"

char *
fmtname(char *path) {
    static char buf[DIRSIZ + 1];
    char *p;

    // Find first character after last slash.
    for (p = path + strlen(path); p >= path && *p != '/'; p--);
    p++;

    // Return blank-padded name.
    if (strlen(p) >= DIRSIZ)
        return p;
    memmove(buf, p, strlen(p));
    memset(buf + strlen(p), ' ', DIRSIZ - strlen(p));
    return buf;
}

void
find(char *path,char *pattern) {
    char buf[512], *p;
    int fd,fd2;
    struct dirent de;
    struct stat st;

    if ((fd = open(path, 0)) < 0) {
        fprintf(2, "ls: cannot open %s\n", path);
        return;
    }

    if (fstat(fd, &st) < 0) {
        fprintf(2, "ls: cannot stat %s\n", path);
        close(fd);
        return;
    }

    if (st.type != T_DIR) {
        fprintf(2, "ls: cannot find from file\n");
        close(fd);
        return;
    }

    strcpy(buf, path);
    p = buf + strlen(buf);
    *p++ = '/';
    while (read(fd, &de, sizeof(de)) == sizeof(de)) {
        if (de.inum == 0)
            continue;

        if(strcmp(de.name,".")==0||strcmp(de.name,"..")==0)continue;
        memmove(p, de.name, strlen(de.name));
        p[strlen(de.name)] = 0;
        if ((fd2 = open(buf, 0)) < 0) {
            fprintf(2, "ls: cannot open %s\n", buf);
            return;
        }

        if (fstat(fd2, &st) < 0) {
            fprintf(2, "ls: cannot stat %s\n", path);
            close(fd2);
            return;
        }

        switch (st.type) {
            case T_DEVICE:
            case T_FILE:
                if(strcmp(de.name,pattern)==0){
                    printf("%s\n", buf);
                }
                break;

            case T_DIR:
                find(buf,pattern);
                break;
        }
        close(fd2);
    }
    close(fd);
}

int
main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(2, "find error\n");
        exit(1);
    }
    find(argv[1],argv[2]);
    exit(0);
}
