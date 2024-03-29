#include "user/user_lib.h"

int main(int argc, char *argv[]){
    char buf[256];
    for(int i=1;i<argc;i++){
        int fd=open(argv[i],O_RDONLY);
        if(fd<0){
            printu("%s:Cannot open file!\n",argv[i]);
            continue;
        }
        struct istat stat;
        if(stat_u(fd,&stat)){
            printu("%s:Stat error!\n",argv[i]);
            close(fd);
            continue;
        }
        int read_size=255<stat.st_size?255:stat.st_size;
        for(int i=0;i<stat.st_size;i+=read_size,read_size=255<stat.st_size-i?255:stat.st_size-i){
            if(read_u(fd,buf,read_size)!=read_size){
                printu("%s:Read error!\n",argv[i]);
                close(fd);
                break;
            }
            buf[read_size]='\0';
            printu(buf);
        }
        close(fd);
    }
    exit(0);
}