#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f)
{
   char* esp = f->esp;
   int syscallNum;

   syscallNum = *((int*)esp);

   switch(syscallNum)
   {
    case SYS_HALT:
      break;
    case SYS_EXIT:
      exit(*((int*)esp+4));
      break;
    case SYS_EXEC:
    /* */
      break;
    case SYS_WAIT:
      break;
    case SYS_CREATE :
      break;
    case SYS_REMOVE :
      break;
    case  SYS_OPEN:
      break;
    case SYS_FILESIZE :
      break;
    case  SYS_READ:
      break;
    case SYS_WRITE:
      write(*((int*)(esp+4)), *((char**)(esp+8)), *((unsigned*)(esp+12)));
      break;
    case SYS_SEEK:
      break;
    case SYS_TELL :
      break;
    case SYS_CLOSE:
      break;
   }
   //thread_exit ();
}

void exit(int status)
{
  printf("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit();
}

int write (int fd, const void *buffer, unsigned size)
{
  if(fd == 1)
  {
    putbuf(buffer, size);

    int len = strlen(buffer);
    return len < size ? len : size;
  }
  else
  {
    // Not yet implemented
  }
}
