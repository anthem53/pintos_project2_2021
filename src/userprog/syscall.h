#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
int write (int fd, const void *buffer, unsigned size);
void exit(int status);
int  exec ( char * cmd_line);
int wait(int tid);

#endif /* userprog/syscall.h */
