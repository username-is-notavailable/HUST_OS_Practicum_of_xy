/*
 * accessing host files by using the Spike interface.
 *
 * PKE OS needs to access the host file duing its execution to conduct ELF (application) loading.
 *
 * codes are borrowed from riscv-pk (https://github.com/riscv/riscv-pk)
 */

#include "spike_file.h"
#include "spike_htif.h"
#include "atomic.h"
#include "string.h"
#include "util/functions.h"
#include "spike_interface/spike_utils.h"
//#include "../kernel/config.h"

static spike_file_t* spike_fds[MAX_FDS];
spike_file_t spike_files[MAX_FILES] = {[0 ... MAX_FILES - 1] = {-1, 0}};

void copy_stat(struct stat* dest_va, struct frontend_stat* src) {
  struct stat* dest = (struct stat*)dest_va;
  dest->st_dev = src->dev;
  dest->st_ino = src->ino;
  dest->st_mode = src->mode;
  dest->st_nlink = src->nlink;
  dest->st_uid = src->uid;
  dest->st_gid = src->gid;
  dest->st_rdev = src->rdev;
  dest->st_size = src->size;
  dest->st_blksize = src->blksize;
  dest->st_blocks = src->blocks;
  dest->st_atime = src->atime;
  dest->st_mtime = src->mtime;
  dest->st_ctime = src->ctime;
}

int spike_file_stat(spike_file_t* f, struct stat* s) {
  struct frontend_stat buf;
  uint64 pa = (uint64)&buf;
  long ret = frontend_syscall(HTIFSYS_fstat, f->kfd, (uint64)&buf, 0, 0, 0, 0, 0);
  copy_stat(s, &buf);
  return ret;
}

int spike_file_close(spike_file_t* f) {
  if (!f) return -1;
  spike_file_t* old = atomic_cas(&spike_fds[f->kfd], f, 0);
  spike_file_decref(f);
  if (old != f) return -1;
  spike_file_decref(f);
  return 0;
}

void spike_file_decref(spike_file_t* f) {
  atomic_add(&f->refcnt, -1);
  if (f->refcnt == 2) {
    int kfd = f->kfd;
    mb();
    atomic_set(&f->refcnt, 0);
    frontend_syscall(HTIFSYS_close, kfd, 0, 0, 0, 0, 0, 0);
  }
}

void spike_file_incref(spike_file_t* f) {
  long prev = atomic_add(&f->refcnt, 1);
  kassert(prev > 0);
}

ssize_t spike_file_write(spike_file_t* f, const void* buf, size_t size) {
  return frontend_syscall(HTIFSYS_write, f->kfd, (uint64)buf, size, 0, 0, 0, 0);
}

int spike_file_readdir(char *path, char *d_name, int *offset, char *type){
  // sprint("spike_file_readdir:path:%s offset:%d\n",path,*offset);
  int ret = frontend_syscall(HTIFSYS_readdir,(uint64)path,strlen(path)+1,(uint64)d_name,(*offset)++,(uint64)type,0,0);
  if (*type==8||*type==10)*type=FILE_I;
  else if (*type==4)*type=DIR_I;
  return ret;
}

static spike_file_t* spike_file_get_free(void) {
  for (spike_file_t* f = spike_files; f < spike_files + MAX_FILES; f++)
    if (atomic_read(&f->refcnt) == 0 && atomic_cas(&f->refcnt, 0, INIT_FILE_REF) == 0)
      return f;
  return NULL;
}

int spike_file_dup(spike_file_t* f) {
  for (int i = 0; i < MAX_FDS; i++) {
    if (atomic_cas(&spike_fds[i], 0, f) == 0) {
      spike_file_incref(f);
      return i;
    }
  }
  return -1;
}

void spike_file_init(void) {
  // create stdin, stdout, stderr and FDs 0-2
  for (int i = 0; i < 3; i++) {
    spike_file_t* f = spike_file_get_free();
    f->kfd = i;
    spike_file_dup(f);
  }
}

spike_file_t* spike_file_openat(int dirfd, const char* fn, int flags, int mode) {
  spike_file_t* f = spike_file_get_free();
  if (f == NULL) return ERR_PTR(-ENOMEM);

  size_t fn_size = strlen(fn) + 1;
  long ret = frontend_syscall(HTIFSYS_openat, dirfd, (uint64)fn, fn_size, flags, mode, 0, 0);
  if (ret >= 0) {
    f->kfd = ret;
    return f;
  } else {
    spike_file_decref(f);
    if(ret==-2)return NULL;
    return ERR_PTR(ret);
    // return NULL;
  }
}

spike_file_t* spike_file_open(const char* fn, int flags, int mode) {
  return spike_file_openat(AT_FDCWD, fn, flags, mode);
}

int spike_file_mkdir(const char* fn, int mode){
  return frontend_syscall(HTIFSYS_mkdirat,AT_FDCWD,(uint64)fn,strlen(fn)+1,mode,0,0,0);
}

ssize_t spike_file_pread(spike_file_t* f, void* buf, size_t size, off_t offset) {
  return frontend_syscall(HTIFSYS_pread, f->kfd, (uint64)buf, size, offset, 0, 0, 0);
}

ssize_t spike_file_read(spike_file_t* f, void* buf, size_t size) {
  return frontend_syscall(HTIFSYS_read, f->kfd, (uint64)buf, size, 0, 0, 0, 0);
}

ssize_t spike_file_lseek(spike_file_t* f, size_t ptr, int dir) {
  return frontend_syscall(HTIFSYS_lseek, f->kfd, ptr, dir, 0, 0, 0, 0);
}

int spike_file_link(const char* old, const char* new, int flag){
  return frontend_syscall(HTIFSYS_linkat, AT_FDCWD, (uint64)old, strlen(old)+1, AT_FDCWD, (uint64)new, strlen(new)+1, flag);
}

int spike_file_unlink(const char* name, int flag){
  return frontend_syscall(HTIFSYS_unlinkat, AT_FDCWD, (uint64)name, strlen(name)+1, flag, 0, 0, 0);
}

spike_file_t* spike_file_get(int fd) {
  spike_file_t* f;
  if (fd < 0 || fd >= MAX_FDS || (f = atomic_read(&spike_fds[fd])) == NULL)
    return 0;

  long old_cnt;
  do {
    old_cnt = atomic_read(&f->refcnt);
    if (old_cnt == 0)
      return 0;
  } while (atomic_cas(&f->refcnt, old_cnt, old_cnt+1) != old_cnt);

  return f;
}

uint64 spike_wait_for_a_key(){
  return frontend_syscall(HTIFSYS_wait_for_a_key, 0, 0, 0, 0, 0, 0, 0);
}

int spike_get_stdin_buf(char *buf, int max_len){
  return frontend_syscall(HTIFSYS_get_stdin_buf, (uint64)buf, max_len, 0, 0, 0, 0, 0);
}