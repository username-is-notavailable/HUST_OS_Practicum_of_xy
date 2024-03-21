#include "user_lib.h"
#include "util/types.h"

int main(void){
    int fd=opendir_u("/test");
    printu("!!!!!!!!!!!!!%d\n",fd);
    struct dir d;
    while(readdir_u(fd,&d)){
        printu("%s\n",d.name);
    }
    exit(0);
}