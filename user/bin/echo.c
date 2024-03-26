#include "user/user_lib.h"

int main(int argc, char *argv[]){
    // printu("%d %p\n",argc,argv);
    for(int i=1;i<argc;i++)
        printu("%s ",argv[i]);
    printu("\n");
    exit(0);
    return 0;
}