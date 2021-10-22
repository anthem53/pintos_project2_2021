#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

/* Own functions for project2 */
int push_string(char * s , void ** esp, int len);
char * strrev (char * c) ;
void push_char(char c, void** esp);
void push_null_ntimes(int n, void** esp);

#endif /* userprog/process.h */
