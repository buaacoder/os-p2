#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"
#include "process.h"
#include <string.h>
#include "devices/shutdown.h"
#define MAXARGC 200

static void syscall_handler (struct intr_frame *);
int IWrite(int fd, char *buffer, unsigned size);
void IExit(int status);
int ICreate(const char *file, unsigned initial_size);
int IOpen(const char *f);
void IClose(int fd);
int IRead(int fd, char *buffer, unsigned size);
int IFileSize(int fd);
int IExec(const char *file);
int IWait(int tid);
void ISeek(int fd, unsigned pos);
int IRemove(const char *file);
void IHalt();
unsigned ITell(int fd);

struct file_node *GetFile(struct thread *t, int fd);


void acquire_args (const struct intr_frame *f, void *arg, unsigned count){
    struct thread *cur = thread_current();
    int32_t *esp = f->esp;
    int32_t *args = arg;
    int i = 0;
    for(i=0; i<=count+1; i++){
      if(!is_user_vaddr(esp)||esp<=(void*)0x08048000)
      {
        IExit(-1);
      }
      char *p = esp;
      while(pagedir_get_page(cur->pagedir, p)!=NULL && *p)
      {
        p++;
      }
      if(pagedir_get_page(cur->pagedir, p)==NULL)
      {
        IExit(-1);
      }
      args[i] = *esp;
      esp++;
    }
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  int arg[MAXARGC];
  struct thread *cur = thread_current();
  if(!is_user_vaddr((char *)f->esp)||f->esp<(void*)0x08048000)
  {
    IExit(-1);
  }
  char *p = f->esp;
  while(pagedir_get_page(cur->pagedir, p)!=NULL && *p)
  {
    p++;
  }
  if(pagedir_get_page(cur->pagedir, p)==NULL)
  {
    IExit(-1);
  }
  int No = *((int *)(f->esp));
  // printf("%d\n",No);
  if(No==SYS_EXIT)
  {
    acquire_args(f, arg, 1);
    IExit(arg[1]);
  }else if(No==SYS_WRITE)
  {
    acquire_args(f, arg, 3);
    f->eax = IWrite(arg[1], (void *)arg[2], (unsigned)arg[3]);
  }else if(No==SYS_OPEN)
  {
    acquire_args(f, arg, 1);
    f->eax = IOpen((char *)arg[1]);
  }else if(No==SYS_CLOSE)
  {
    acquire_args(f, arg, 1);
    IClose(arg[1]);
  }else if(No==SYS_CREATE)
  {
    acquire_args(f, arg, 2);
    f->eax = ICreate((char *)arg[1], (unsigned)arg[2]);
  }else if(No==SYS_READ)
  {
    acquire_args(f, arg, 3);
    f->eax = IRead(arg[1], (char *)arg[2], (unsigned)arg[3]);
  }else if(No==SYS_FILESIZE)
  {
    acquire_args(f, arg, 1);
    f->eax = IFileSize(arg[1]);
  }else if(No==SYS_WAIT)
  {
    acquire_args(f, arg, 1);
    f->eax = IWait(arg[1]);
  }else if(No==SYS_EXEC)
  {
    acquire_args(f, arg, 1);
    f->eax = IExec((char *)arg[1]);
  }else if(No==SYS_SEEK)
  {
    acquire_args(f, arg, 2);
    ISeek(arg[1], arg[2]);
  }else if(No==SYS_REMOVE)
  {
    acquire_args(f, arg, 1);
    f->eax = IRemove((char *)arg[1]);
  }else if(No==SYS_TELL)
  {
    acquire_args(f, arg, 1);
    f->eax = ITell(arg[1]);
  }else if(No==SYS_HALT)
  {
    IHalt();
  }else
  {
    IExit(-1);
  }
}

void IExit(int status)
{
  struct thread *t = thread_current();
  t->ret = status;
  thread_exit();
}

int IOpen(const char *f)
{
  struct thread *cur = thread_current();
  struct file_node *fn = (struct file_node *)malloc(sizeof(struct file_node));
  if(f==NULL)
  {
    IExit(-1);
  }
  if(!is_user_vaddr(f)||f<(void*)0x08048000)
  {
    IExit(-1);
  }
  char *p = f;
  while(pagedir_get_page(cur->pagedir, p)!=NULL && *p)
  {
    p++;
  }
  if(pagedir_get_page(cur->pagedir, p)==NULL)
  {
    IExit(-1);
  }
  fn->f = filesys_open(f);
  if(fn->f==NULL||cur->next_fd<0)
  {
    fn->fd = -1;
  }else
  {
    fn->fd = cur->next_fd;
    cur->next_fd++;
  }
  if(fn->fd==-1)
  {
    free(fn);
    return -1;
  }else
  {
    list_push_back(&cur->file_list, &fn->elem);
    return fn->fd;
  }
}

void IClose(int fd)
{
  struct thread *cur = thread_current();
  struct list_elem *l_elem;
  struct file *f = NULL;
  for(l_elem=list_begin(&cur->file_list);l_elem!=list_end(&cur->file_list);l_elem=list_next(l_elem))
  {
    struct file_node *fn = list_entry(l_elem, struct file_node, elem);
    if(fd == fn->fd)
    {
      f = fn->f;
      break;
    }
  }
  if(f==NULL)
  {
    IExit(-1);
  }
  file_close(f);
  list_remove(l_elem);
  free(list_entry(l_elem, struct file_node, elem));
}

int ICreate(const char *file, unsigned initial_size)
{
  struct thread *cur = thread_current();
  if(file==NULL)
  {
    IExit(-1);
  }
  if(!is_user_vaddr(file)||file<(void*)0x08048000)
  {
    IExit(-1);
  }
  char *p = file;
  while(pagedir_get_page(cur->pagedir, p)!=NULL && *p)
  {
    p++;
  }
  if(pagedir_get_page(cur->pagedir, p)==NULL)
  {
    IExit(-1);
  }
  if(strlen(file)==0)
  {
    return 0;
  }
  bool ret =  filesys_create(file, initial_size);
  return ret;
}

int IRead(int fd, char *buffer, unsigned size)
{
  if(buffer==NULL||!is_user_vaddr(buffer+size)||buffer<(void*)0x08048000)
  {
    IExit(-1);
  }
  struct thread *cur = thread_current();
  unsigned i = 0;
  char *p = buffer;
  while(i < size){
      if(pagedir_get_page(cur->pagedir, &p[i]) == NULL)
      {
        return -1;
      }
      i++;
  }
  if(fd==0)
  {
    for(i=0;i<size;i++)
    {
      buffer[i]=input_getc();
    }
  }else
  {
    struct list_elem *l_elem;
    struct file_node *fn = NULL;
    for(l_elem=list_begin(&cur->file_list);l_elem!=list_end(&cur->file_list);l_elem=list_next(l_elem))
    {
      fn = list_entry(l_elem, struct file_node, elem);
      if(fd == fn->fd)
      {
        return file_read(fn->f, buffer, size);
      }
    }
    return -1;
  }
}

int IWrite(int fd, char *buffer, unsigned size)
{
  if(buffer==NULL||!is_user_vaddr(buffer+size)||buffer<(void*)0x08048000)
  {
    IExit(-1);
  }
  struct thread *cur = thread_current();
  unsigned i = 0;
  char *p = buffer;
  while(i < size){
      if(pagedir_get_page(cur->pagedir, &p[i]) == NULL)
      {
        IExit(-1);
      }
      i++;
  }
  if(fd==1)
  {
    putbuf(buffer, size);
    // printf("%d\n",size);
    return size;
  }else
  {
    struct list_elem *l_elem;
    struct file_node *fn = NULL;
    for(l_elem=list_begin(&cur->file_list);l_elem!=list_end(&cur->file_list);l_elem=list_next(l_elem))
    {
      fn = list_entry(l_elem, struct file_node, elem);
      if(fd == fn->fd)
      {
        return file_write(fn->f, buffer, size);
      }
    }
    return -1;
  }
}

int IFileSize(int fd)
{
  struct thread *cur = thread_current();
  struct list_elem *l_elem;
  struct file_node *fn = NULL;
  for(l_elem=list_begin(&cur->file_list);l_elem!=list_end(&cur->file_list);l_elem=list_next(l_elem))
  {
    fn = list_entry(l_elem, struct file_node, elem);
    if(fd == fn->fd)
    {
      return file_length(fn->f);
    }
  }
  return -1;
}

int IExec(const char *file)
{
  struct thread *cur = thread_current();
  if(file==NULL)
  {
    IExit(-1);
  }
  if(!is_user_vaddr(file)||file<(void*)0x08048000)
  {
    IExit(-1);
  }
  char *p = file;
  while(pagedir_get_page(cur->pagedir, p)!=NULL && *p)
  {
    p++;
  }
  if(pagedir_get_page(cur->pagedir, p)==NULL)
  {
    IExit(-1);
  }
  char *new = (char *)malloc(strlen(file)+1);
  memcpy(new, file, strlen(file)+1);
  // printf("hhhhhhhhhhhhhhhhhhhhhh55\n");
  tid_t tid = process_execute(new);
  struct thread *son = get_thread_by_tid(tid);
  if(son==NULL)
  {
    free(new);
    IExit(-1);
  }
  son->father = cur;
  // printf("%d\n",son->tid);
  sema_down(&son->sema_load);
  int res = son->tid;
  free(new);
  if(res==-1)
  {
    list_remove(&(son->son_elem));
  }
  // printf("hhhhhhhhhhhhhhhhhhhhhh77\n");
  sema_up(&son->get_msg);
  // printf("hhhhhhhhhhhhhhhhhhhhhh88\n");
  thread_yield();
  return res;
}

int IWait(int tid)
{
  if(tid!=-1)
  {
    return process_wait(tid);
  }else
  {
    return -1;
  }
}

void ISeek(int fd, unsigned pos)
{
  struct thread *cur = thread_current();
  struct list_elem *l_elem;
  struct file *f = NULL;
  for(l_elem=list_begin(&cur->file_list);l_elem!=list_end(&cur->file_list);l_elem=list_next(l_elem))
  {
    struct file_node *fn = list_entry(l_elem, struct file_node, elem);
    if(fd == fn->fd)
    {
      f = fn->f;
      break;
    }
  }
  if(f==NULL)
  {
    IExit(-1);
  }
  file_seek(f, pos);
}

int IRemove(const char *file)
{
  struct thread *cur = thread_current();
  char *p = file;
  if(file==NULL)
  {
    IExit(-1);
  }
  if(!is_user_vaddr(file)||file<(void*)0x08048000)
  {
    IExit(-1);
  }
  while(pagedir_get_page(cur->pagedir, p)!=NULL && *p)
  {
    p++;
  }
  if(pagedir_get_page(cur->pagedir, p)==NULL)
  {
    IExit(-1);
  }
  return filesys_remove(file);
}

unsigned ITell(int fd)
{
  struct thread *cur = thread_current();
  struct list_elem *l_elem;
  struct file *f = NULL;
  for(l_elem=list_begin(&cur->file_list);l_elem!=list_end(&cur->file_list);l_elem=list_next(l_elem))
  {
    struct file_node *fn = list_entry(l_elem, struct file_node, elem);
    if(fd == fn->fd)
    {
      f = fn->f;
      break;
    }
  }
  if(f==NULL)
  {
    IExit(-1);
  }
  return file_tell(f);
}

void IHalt()
{
  shutdown_power_off();
}