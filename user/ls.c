#include "user_lib.h"
#include "util/string.h"

int main(int argc, char *argv[]){
    // printu("start\n");
    char path[256];
    if(argc<2) read_cwd(path); 
    else strcpy(path,argv[1]);
    // printu("%s\n",path);
    int dir_fd = opendir_u(path);
    if(dir_fd<0){
        printu("Cannot open dir %s!\n",path);
        exit(0);
    }
    // printu("---------- ls command -----------\n");
    // printu("ls \"%s\":\n", path);
    // printu("[name]               [inode_num]\n");
    struct dir dir;
    int width = 20;
    int line_num=0;
    while(readdir_u(dir_fd, &dir) == 0) {
        // we do not have %ms :(
        char name[width + 1];
        memset(name, ' ', width + 1);
        name[width] = '\0';
        if (strlen(dir.name) < width) {
            strcpy(name, dir.name);
            if(dir.type==DIR_I)printu("\033[34m");
            name[strlen(dir.name)] = ' ';
            printu("%s\033[0m", name);
        }
        else
            printu("%s ", dir.name);
        if(++line_num==5){
            printu("\n");
            line_num=0;
        }
    }
    if(line_num)printu("\n");
    closedir_u(dir_fd);
    exit(0);
}