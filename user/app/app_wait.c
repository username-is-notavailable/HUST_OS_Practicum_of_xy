/*
 * This app fork a child process, and the child process fork a grandchild process.
 * every process waits for its own child exit then prints.                     
 * Three processes also write their own global variables "flag"
 * to different values.
 */

#include "user/user_lib.h"
#include "util/types.h"

int flag=0;
int main(void) {
    flag = 0;
    char test[4096]="Aaaaaaaaaaa";
    int test_i=123;
    int pid = fork();
    printu("%d %s %d\n",pid,test,test_i);
    if (pid == 0) {
        flag = 1;
        pid = fork();
        if (pid == 0) {
            flag = 2;
            printu("Grandchild process end, flag = %d.\n", flag);
        } else {
            wait(pid);
            printu("Child process end, flag = %d.\n", flag);
        }
    } else {
        wait(-1);
        printu("Parent process end, flag = %d.\n", flag);
    }
    exit(0);
    return 0;
}
