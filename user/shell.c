/*This is a simple shell*/

#include "user_config.h"
#include "user_lib.h"
#include "util/types.h"
#include "util/string.h"

#define INFO(cwd)  (printu("\033[32mmyshell\033[0m:\033[34m%s\033[0m$ ",(cwd)))

#define add_global_var(name, value) __global_variables.virtual_hash_put(&__global_variables,(name),(value))
#define delete_global_var(name) __global_variables.virtual_hash_erase(&__global_variables,(name))
#define get_global_var(name) __global_variables.virtual_hash_get(&__global_variables,(name))

typedef struct parse_str_t{
    int total,offset;
    char *str,*next;
    bool alloc;
}parse_str;


void get_input(char *buf);
int get_frag(char *des, char *buf, int pos, int spilt);
bool is_contain(char *longer, char *shorter);
void get_base_name(const char *path, char *base_name);
size_t hash_function(void* key);
int hash_equal(void* key1, void *key2);
parse_str *parse_string(char*string, int delim, bool alloc);
void free_parse_str(parse_str *p);
char *get_string(parse_str *pstr);
int source(char *path);
void do_command(char *command);
char *replace_global_va(char *des, char *src);

static int hash_malloc_put(struct hash_table *hash_table, void *key, void *value);
static int hash_free_erase(struct hash_table *hash_table, void *key);

static struct hash_table __global_variables;

int main(int arg, char *argv[]){
    char input_buf[SHELL_BUF_MAX],path[SHELL_BUF_MAX*2];
    bool shutdown=FALSE;
    hash_table_init(&__global_variables,
        hash_equal,
        hash_function,
        hash_malloc_put,
        NULL,
        hash_free_erase
    );

    source("/etc/profile");

    for(int i=0;i<HASH_TABLE_SIZE;i++)
        for(struct hash_node *p=(__global_variables.head+i)->next;p;p=p->next)printu("%s = %s\n",p->key,p->value);

    while (!shutdown){
        get_input(input_buf);
        // printu("%s\n",input_buf);
        do_command(input_buf);
        
    }
}

void get_input(char *buf){
    int p=0,len=0;
    char temp_str[128],cwd[128];
    int temp=0;
    read_cwd(cwd);
    INFO(cwd);
    buf[len]='\0';
    while(TRUE){
        temp=getch();
        // printu("(%d)",temp);
        // temp=0;
        switch (temp)
        {
            case 0x7f:    //backspce
                if(p>0&&len>0){
                    // printu("%d %d",p,len);
                    printu("\b");
                    for(int i=p-1;i<len;i++)buf[i]=buf[i+1];
                    int back=printu("%s",buf+p-1);
                    printu(" ");
                    for(int i=0;i<back+1;i++)printu("\b");
                    p--;
                    len--;
                }
                break;
            case 27:
                // printu("@@@@@@@@@@@@@@@@@@@@@@@@@\n");
                temp=getch();
                // printu("%x",temp);
                if(temp==0x5b){
                    temp=getch();
                    // printu("[%x]",temp);
                    if(temp==0x41)/*上*/;
                    if(temp==0x42)/*下*/;
                    if(temp==0x43&&p<len)/*右*/printu("%c",buf[p++]);
                    if(temp==0x44&&p>0)/*左*/{
                        // printu("%d %d",p,len);
                        printu("\b");
                        p--;
                    }
                }
                break;
            case '\t':
                int pt,flen=get_frag(temp_str,buf,p,' '),find=0;
                char base_name[128];
                pt=flen-1;
                while(pt>0&&temp_str[pt]!='/')pt--;
                strcpy(base_name,temp_str+pt+(temp_str[pt]=='/'?1:0));
                // printu(" %s",base_name);
                temp_str[flen-strlen(base_name)]='\0';
                // printu("%s",temp_str);
                int fd = opendir_u(temp_str);
                // printu("%s %d\n",temp_str,fd);
                if(fd<0)break;
                struct dir d;
                while(readdir_u(fd,&d)==0){
                    if(d.type==DIR_I)strcat(temp_str,"/");
                    // printu("\n %s %s\n",d.name,base_name);
                    if(is_contain(d.name,base_name)){
                        if(find==0){
                            find++;
                            strcpy(temp_str,d.name);
                        }
                        else{
                            if(find==1)printu("\n%s\n",temp_str);
                            printu("%s\n",d.name);
                            find++;
                        }
                    }
                }
                if(find==1){
                    int base_len=strlen(base_name), insert_len=strlen(temp_str)-base_len;
                    for(int i=len;i>=p;i--)buf[i+insert_len]=buf[i];
                    len+=insert_len;
                    for(int i=0;i<insert_len;i++)buf[p+i]=temp_str[base_len+i];
                    int ret_len=printu("%s",buf+p)-insert_len;
                    p+=insert_len;
                    // printu("(%d)",ret_len);
                    for(int i=0;i<ret_len;i++)printu("\b");
                }
                else if(find){
                    INFO(cwd);
                    printu("%s",buf);
                    for(int i=0;i<len-p;i++)printu("\b");
                }
                
                if(fd>=0)closedir_u(fd);
                break;
            case '\n':
                printu("\n");
                buf[len]='\0';
                return;
            default:
                for(int i=len;i>p;i--)buf[i]=buf[i-1];
                buf[p]=temp;
                buf[++len]='\0';
                printu("%s",buf+p);
                p++;
                for(int i=p;i<len;i++)printu("\b");
                break;
        }
    }
    
}

int get_frag(char *des, char *buf, int pos, int spilt){
    int i=pos;
    while(i>0&&buf[i-1]!=spilt)i--;
    
    for(int j=0;i<pos;j++,i++)des[j]=buf[i];
    des[i]='\0';
    return i;
}

bool is_contain(char *longer, char *shorter){
    while(*shorter){
        if(*longer!=*shorter)return FALSE;
        shorter++;
        longer++;
        if(*longer=='\0')return FALSE;
    }
    return TRUE;
}

void get_base_name(const char *path, char *base_name) {
  char path_copy[MAX_PATH_LEN];
  strcpy(path_copy, path);

  char *token = strtok(path_copy, "/");
  char *last_token = NULL;
  while (token != NULL) {
    last_token = token;
    token = strtok(NULL, "/");
  }

  strcpy(base_name, last_token);
}

size_t hash_function(void* key){
    ssize_t i=0;
    while(*(char*)key)i+=*(char*)(key++);
    return i%HASH_TABLE_SIZE;
}

int hash_equal(void* key1, void *key2){
    return !strcmp((char*)key1, (char*)key2);
}

static int hash_malloc_put(struct hash_table *hash_table, void *key, void *value) {
  struct hash_node *node = (struct hash_node *)better_malloc(sizeof(struct hash_node));
  if (hash_table->virtual_hash_get(hash_table, key) != NULL) return -1;
  node->key = better_malloc(64);
  strcpy(node->key, key);
  node->value = better_malloc(2048);
  strcpy(node->value, value);

  size_t index = hash_table->virtual_hash_func(key);
  struct hash_node *head = hash_table->head + index;

  node->next = head->next;
  head->next = node;
  return 0;
}

static int hash_free_erase(struct hash_table *hash_table, void *key) {
  size_t index = hash_table->virtual_hash_func(key);
  struct hash_node *head = hash_table->head + index;
  while (head->next && !hash_table->virtual_hash_equal(head->next->key, key))
    head = head->next;
  if (head->next) {
    // printu("%p %p %p\n",head->next,head->next->key,head->next->value);
    struct hash_node *node = head->next;
    head->next = node->next;
    better_free(node->key);
    better_free(node->value);
    better_free(node);
    return 0;
  } else
    return -1;
}

parse_str *parse_string(char*string, int delim, bool alloc){
    parse_str *new_pstr=(parse_str *)better_malloc(sizeof(parse_str));
    char *p1=string,*p2=string;
    if(alloc)p1=better_malloc(strlen(string)+1);
    bool last_is_delim=TRUE;
    new_pstr->str=new_pstr->next=p1;
    new_pstr->offset=0;
    new_pstr->total=1;
    new_pstr->alloc=alloc;
    while(*p2){
        if(*p2==delim&&!last_is_delim)*(p1++)='\0',last_is_delim=TRUE,new_pstr->total++;
        else if(*p2!=delim)*(p1++)=*p2,last_is_delim=FALSE;
        p2++;
    }
    // printu("total:%d\n",new_pstr->total);
    *p1='\0';
    return new_pstr;
}

void free_parse_str(parse_str *p){
    if(p->alloc)better_free(p->str);
    better_free(p);
}

char *get_string(parse_str *pstr){
    if(pstr->offset>=pstr->total)return NULL;
    pstr->offset++;
    char *ret=pstr->next;
    if(pstr->offset<pstr->total)pstr->next+=strlen(pstr->next)+1;
    else pstr->next=NULL;
    return ret;
}

int source(char *path){
    int fd=open(path, O_RDONLY);
    if(fd<0)return -1;

    struct istat stat;
    if(stat_u(fd,&stat)<0)return -2;

    char *content=better_malloc(stat.st_size+1);
    if(!content)return -3;

    if(read_u(fd,content,stat.st_size)!=stat.st_size)return -4;

    content[stat.st_size]='\0';
    // printu("%s\n\n\n\n\n\n------------------------------------------",content);

    parse_str *lines=parse_string(content,'\n',FALSE);
    char *command;
    while((command=get_string(lines)))do_command(command);

    free_parse_str(lines);
    better_free(content);

    return 0;
}

void do_command(char *command){
    // printu("%s\n",command);
    char command_t[2048];
    replace_global_va(command_t,command);
    parse_str *words=parse_string(command_t, ' ', TRUE);
    char *word = get_string(words);
    // printu("%s\n",word);
    if(!strcmp(word,"export")){
        word=get_string(words);
        if(!word){
            printu("too few args!\n");
            free_parse_str(words);
            return;
        }
        parse_str *vars=parse_string(word, '=', FALSE);
        char *name=get_string(vars);
        char *value=get_string(vars);
        if(!name||!value){
            printu("error type!\n");

        }
        // printu("name:%s\n",name);
        if(get_global_var(name))delete_global_var(name);
        add_global_var(name,value);
    }
    else if(!strcmp(word,"cd")){
        word=get_string(words);
        if(!word){
            printu("too few args!\n");
            free_parse_str(words);
            return;
        }
        change_cwd(word);
    }
    else{
        char path[256];
        strprint(path,"/bin/%s",word);
        // printu("%s\n",path);
        // printu("%s %s",path,command_t);
        int pid=fork();
        if(pid==0)
            // printu("%s %s",path,command_t);
            exec(path,command_t);
        else wait(pid);
    }
}

char *replace_global_va(char *des, char *src){
    char*p=des;
    while(*src){
        if(*src=='$'){
            char name[64];
            char *pname=name;
            src++;
            while((*src>='a'&&*src<='z')||
                (*src>='A'&&*src<='Z')||
                (*src>='0'&&*src<='9'))*(pname++)=*(src++);
            *pname='\0';
            char *value=get_global_var(name);
            if(value)while(*value)*(p++)=*(value++);

            if(*src=='\0')break;
        }
        else *(p++)=*(src++);
    }    
    *p='\0';
    return des;
}
