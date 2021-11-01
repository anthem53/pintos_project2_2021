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
   tid_t result =-190;

   syscallNum = *((int*)esp);

   switch(syscallNum)
   {
    case SYS_HALT:
      shutdown_power_off();
      break;
    case SYS_EXIT:
      exit(*((int*)(esp+4)));
      break;
    case SYS_EXEC:
      f->eax = exec(*((char**)(esp+4)));
      break;
    case SYS_WAIT:
      f->eax = wait(*((tid_t*)(esp+4)));
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
      f->eax = write(*((int*)(esp+4)), *((char**)(esp+8)), *((unsigned*)(esp+12)));
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
  struct thread * cur = thread_current();
  printf("%s: exit(%d)\n", cur->name, status);

  list_remove(&cur->child_elem);

  if( cur == cur->parent->child_for_waiting)
  {
    cur->parent->child_exit_status = status;
    thread_unblock(cur->parent);
  }

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

  return 0;
}

int  exec( char * cmd_line)
{
  int result = process_execute(cmd_line);
  struct thread * child = thread_get_with_tid(result);

  return result;
}

int wait(tid_t tid)
{
  return process_wait(tid);

}
