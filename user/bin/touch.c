#include "user/user_lib.h"
#include "util/types.h"

int main(int argc, char* argv[]){
    if(argc<2)printu("Too few args!\n");
    else{
        int fd=open(argv[1],O_RDONLY | O_CREAT);
        if(fd<0)printu("Cannot create file %s!\n",argv[1]);
        else close(fd);
    }
    exit(0);
}