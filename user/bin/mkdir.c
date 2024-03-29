#include "user/user_lib.h"
#include "util/string.h"

int main(int argc, char *argv[]){
    for(int i=1;i<argc;i++)mkdir_u(argv[i]);
    exit(0);
}