#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H


void syscall_init (void);
int write (int fd, const void *buffer, unsigned size);
void exit(int status);
int  exec ( char * cmd_line);
int wait(int tid);
//bool create(char *file, unsigned initial_size);
int open(const char *file);
void close(int fd);
int read (int fd, void * buffer, unsigned size);
int filesize (int fd);
//bool remove (const char *file);
unsigned tell (int fd);
void seek (int fd, unsigned position);


#endif /* userprog/syscall.h */
