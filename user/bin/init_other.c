/*execute shell and then reclaim process whose parent process has exited*/
#include "user/user_lib.h"

int main(void){
    while(!__shutnow()){
        yield();
    }
    exit(0);
}