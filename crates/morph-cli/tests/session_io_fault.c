/* Only LD_PRELOADed into owned test callers. Never linked into Morph binaries. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static char last_path[4096];
static unsigned ordinal;
static int renamed_selected;
static int resolve_fd(int fd, char *path) {
    char link[64]; snprintf(link,sizeof(link),"/proc/self/fd/%d",fd);
    ssize_t n=readlink(link,path,4095); if(n<0)return 0; path[n]=0;return 1;
}
static int selected_path(const char *path) {
    const char *prefix=getenv("MORPH_IO_TMP_PREFIX");
    if(!prefix || strncmp(path,prefix,strlen(prefix)))return 0;
    if(strcmp(last_path,path)) {snprintf(last_path,sizeof(last_path),"%s",path);ordinal++;}
    const char *number=getenv("MORPH_IO_ORDINAL");
    return number && ordinal==(unsigned)strtoul(number,NULL,10);
}
static int selected_fd(int fd) {char path[4096];return resolve_fd(fd,path) && selected_path(path);}
static int mode(const char *value) {const char *m=getenv("MORPH_IO_MODE");return m && !strcmp(m,value);}
static void hit(void) {
    const char *path=getenv("MORPH_IO_HIT");if(!path)return;
    int fd=open(path,O_WRONLY|O_CREAT|O_EXCL,0600);if(fd>=0)close(fd);
}
ssize_t write(int fd,const void *data,size_t size) {
    int selected=selected_fd(fd);
    if(selected && mode("write")){hit();errno=ENOSPC;return -1;}
    ssize_t (*real)(int,const void *,size_t)=dlsym(RTLD_NEXT,"write");
    if(!real){errno=EIO;return -1;}return real(fd,data,size);
}
int fsync(int fd) {
    int selected=selected_fd(fd);char path[4096];const char *parent=getenv("MORPH_IO_PARENT");
    if((selected && mode("sync")) || (renamed_selected && mode("directory") && parent && resolve_fd(fd,path) && !strcmp(path,parent))) {
        hit();errno=EIO;return -1;
    }
    int (*real)(int)=dlsym(RTLD_NEXT,"fsync");if(!real){errno=EIO;return -1;}return real(fd);
}
int rename(const char *old,const char *new_path) {
    int selected=selected_path(old);
    if(selected && mode("rename")){hit();errno=EIO;return -1;}
    int (*real)(const char *,const char *)=dlsym(RTLD_NEXT,"rename");if(!real){errno=EIO;return -1;}
    int result=real(old,new_path);if(selected && !result)renamed_selected=1;return result;
}
