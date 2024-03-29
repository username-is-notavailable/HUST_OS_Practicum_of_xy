#include "user/user_lib.h"
#include "util/types.h"

int main(){
    for(int i=0;i<200;i++){
        int fd=open("hostfile.txt",O_RDONLY);
        if(fd<0)printu("!!!!!!!!!!!!!!!!!!\n");
        else close(fd);
    }
    exit(0);
}