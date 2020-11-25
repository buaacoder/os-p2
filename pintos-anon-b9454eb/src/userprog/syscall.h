#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
int IWrite(int fd, char *buffer, unsigned size);
void IExit(int status);
int ICreate(const char *file, unsigned initial_size);
int IOpen(const char *f);
void IClose(int fd);
int IRead(int fd, char *buffer, unsigned size);
int IFileSize(int fd);
int IExec(const char *file);
int IWait(int tid);

#endif /* userprog/syscall.h */
