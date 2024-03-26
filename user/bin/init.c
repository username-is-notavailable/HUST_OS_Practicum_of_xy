/*execute shell and then reclaim process whose parent process has exited*/
#include "user/user_lib.h"

int main(void){
    if(fork()==0){
        exec("/bin/shell","");
    }
    register_init();
    while(!__shoutnow()){
        wait(-1);
    }
}