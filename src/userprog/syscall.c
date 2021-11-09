#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <list.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "userprog/pagedir.h"



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
   int test;
   tid_t result =-190;
   void * addr = pagedir_get_page(
                      thread_current()->pagedir, f->esp);
   void * addr2 = pagedir_get_page(
                       thread_current()->pagedir, f->esp+3);
   if ( esp >= 0xC0000000)
   {
     exit(-1);
   }
   else if (esp < 0)
   {
     exit(-1);
   }
   if(addr == NULL || addr2 == NULL)
   {
     exit(-1);
   }
  //printf("esp addres value  : %p\n", esp);
   syscallNum = *((int*)esp);
   //printf("syscallNum : %d\n", syscallNum);

   switch(syscallNum)
   {
    case SYS_HALT:
      shutdown_power_off();
      break;
    case SYS_EXIT:
      if(esp+4 >= 0xC0000000)
        exit(-1);
      else
        exit(*((int*)(esp+4)));
      break;
    case SYS_EXEC:
      addr2 = pagedir_get_page(
                     thread_current()->pagedir,    esp + 5    );
      if(addr2 == NULL){
        //printf("addr2 == NULL\n");
        exit(-1);
      }
      f->eax = exec(*((char**)(esp+4)));
      break;
    case SYS_WAIT:
      f->eax = wait(*((tid_t*)(esp+4)));
      break;
    case SYS_CREATE :
      addr = pagedir_get_page(
                       thread_current()->pagedir, *((char**)(esp+4)));
      if(addr == NULL)
        exit(-1);
      else
        f->eax = filesys_create(*((char**)(esp+4)), *((unsigned*)(esp+8)));
      break;
    case SYS_REMOVE :

      f->eax = filesys_remove(*((char**)(esp+4)));
      break;
    case  SYS_OPEN:
      addr = pagedir_get_page(
                       thread_current()->pagedir, *((char**)(esp+4)));
      if(addr == NULL)
        exit(-1);
      f->eax = open(*((char**)(esp+4)));
      break;
    case SYS_FILESIZE :
    f->eax =  filesize(*((int*)(esp+4)));
      break;
    case  SYS_READ:
    test = read(  *((int*)(esp+4)), *((char**)(esp+8)), *((unsigned*)(esp+12))  );
    f->eax = test;
      break;
    case SYS_WRITE:
      //printf("esp : %p\n",esp);
      if(esp+12 >= 0xC0000000)
        exit(-1);
      f->eax = write(*((int*)(esp+4)), *((char**)(esp+8)), *((unsigned*)(esp+12)));
      break;
    case SYS_SEEK:
      break;
    case SYS_TELL :
      break;
    case SYS_CLOSE:
      close(*((int*)(esp+4)));
      break;
   }
   //thread_exit ();
}

unsigned tell (int fd)
{
  struct file * f;
  struct thread * current = thread_current();

  if ( ! (fd > 1 && fd < current->fd_ref)  )
  {
    exit(-1);
  }

  f = thread_current()->fd_table[fd];
  return file_tell(f);
}
void seek (int fd, unsigned position)
{
  struct file * f;
  struct thread * current = thread_current();
  if ( ! (fd > 1 && fd < current->fd_ref)  )
  {
    exit(-1);
  }

  file_seek(fd,position);
  return;
}

int filesize (int fd)
{
  struct thread* current = thread_current();
  if ( ! (fd > 1 && fd < current->fd_ref)  )
  {
    exit(-1);
  }
  struct file * f = current->fd_table[fd];

  if(f != NULL)
  {
      return file_length(f);
  }
  else
  {
    exit(-1);
  }



}
int read (int fd, void * buffer, unsigned size)
{
  struct thread * current = thread_current();
  struct file * f;


  if(fd == 0 )
  {
    int result = input_getc();
    return result;
  }
  else if( ! (fd > 1 && fd < current->fd_ref)  )
  {
    exit(-1);
  }
  else
  {
    if(buffer >=  0xC0000000)
    exit(-1);

    void * addr = pagedir_get_page( thread_current()->pagedir, buffer);
    if(addr == NULL)
      exit(-1);

    f = current->fd_table[fd];
    if(f != NULL)
    {
        int result = file_read(f,buffer,size);

        return result;
    }
    else
    {
      exit(-1);
    }

  }
  return 0;
}

void close(int fd)
{
  struct thread * current = thread_current();
  struct file * f;
  struct thread* t;
  if( ! (fd > 1 && fd < current->fd_ref)  )
  {
    exit(-1);
  }

  f = current->fd_table[fd];
  if( f != NULL){
    file_close(f);
    current->fd_table[fd] = NULL;
  }
  else {
    exit(-1);
  }
}

int open(const char *file)
{
  struct file* f;
  struct thread* current = thread_current();

  struct list_elem* e;
  struct thread* t = get_thread_with_name(file);
  printf("[open] thread t address : %p \n",t);
  if(t != NULL)
  {
    printf("thread name : %s",t->name);
    file_deny_write(f);
  }

  f = filesys_open(file);
  if(f == NULL)
    return -1;
  else
  {
    int result;
    current->fd_table[current->fd_ref] = f;
    result = current->fd_ref;
    (current->fd_ref)++;
    return result;
  }
}

void exit(int status)
{
  struct thread * cur = thread_current();
  int i = 0;
  printf("%s: exit(%d)\n", cur->name, status);

  list_remove(&cur->child_elem);

  if( cur == cur->parent->child_for_waiting)
  {
    cur->parent->child_exit_status = status;
    thread_unblock(cur->parent);
  }


  for( i = 0 ; i < 100 ; i++)
  {
    struct file* f = cur->fd_table[i];
    if(f != NULL)
    {
      file_close(f);
    }
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
  else if( ! (fd > 1 && fd < thread_current()->fd_ref)  )
  {
    exit(-1);
  }
  else
  {

    if(buffer >=  0xC0000000)
      exit(-1);

    void * addr = pagedir_get_page( thread_current()->pagedir, buffer);
    if(addr == NULL)
      exit(-1);

    struct thread * current = thread_current();
    struct file * f =current->fd_table[fd];
    if(f != NULL)
    {
      if(f->deny_write == true)
      {
        file_deny_write(f);
      }
      return file_write(f,buffer,size);
    }
    else
    {
      exit(-1);
    }
  }
}

int  exec( char * cmd_line)
{
  int result;
  struct thread * child = thread_get_with_tid(result);
 char local_cmd_line[15];
 int i = 0;

 void *addr2 = pagedir_get_page( thread_current()->pagedir,    cmd_line + 1    );
 if(addr2 == NULL){
   exit(-1);
 }

 strlcpy(local_cmd_line ,cmd_line, 15);

 for(i = 0 ; i < 15; i++){
   if(local_cmd_line[i] == ' '){
     local_cmd_line[i] = '\0';
     break;
   }
   else if (local_cmd_line[i] == '\0')
   {
     break;
   }
   if(i == 14)
   {
     exit(-1);
   }
 }
 struct file * check_file = filesys_open(local_cmd_line);
  if(check_file == NULL){
    return -1;
  }
  else{
    file_close(check_file);
  }

  result = process_execute(cmd_line);
  return result;
}

int wait(tid_t tid)
{
  return process_wait(tid);
}
