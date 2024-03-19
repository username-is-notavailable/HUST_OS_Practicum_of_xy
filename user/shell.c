/*This is a simple shell*/

#include "user_config.h"
#include "user_lib.h"
#include "util/types.h"

int get_input(char *buf);

int main(int arg, char *argv[]){
    char *input_buf[SHELL_BUF_MAX];
    bool shutdown=FALSE;
    while (!shutdown){
        
    }
}

int get_input(char *buf){
    int p=0;
    printu("myshell");
    while((buf[p]=getch())!='\n'){
        printu("%d",buf[p]);
    }
    return 0;
}