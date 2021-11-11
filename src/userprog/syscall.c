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
#include "threads/synch.h"

struct lock filesys_lock;
struct lock exe_lock;

static void syscall_handler (struct intr_frame *);


void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
  lock_init(&exe_lock);
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
      seek(*((int*)(esp+4)), *((unsigned*)(esp+8)));
      break;
    case SYS_TELL :
      f->eax = tell(*((int*)(esp+4)));
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
  f = thread_current()->fd_table[fd];
  file_seek(f,position);
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

 lock_acquire(&filesys_lock);
  if(fd == 0 )
  {
    int result = input_getc();
    lock_release(&filesys_lock);
    return result;
  }
  else if( ! (fd > 1 && fd < current->fd_ref)  )
  {
    lock_release(&filesys_lock);
    exit(-1);
  }
  else
  {
    if(buffer >=  0xC0000000)
    {
      lock_release(&filesys_lock);
      exit(-1);
    }

    void * addr = pagedir_get_page( thread_current()->pagedir, buffer);
    if(addr == NULL)
    {
      lock_release(&filesys_lock);
      exit(-1);
    }

    f = current->fd_table[fd];
    if(f != NULL)
    {
        int result = file_read(f,buffer,size);
        lock_release(&filesys_lock);
        return result;
    }
    else
    {
      lock_release(&filesys_lock);
      exit(-1);
    }

  }

    lock_release(&filesys_lock);
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
  //printf("[open] thread t address : %p \n",t);
  lock_acquire(&filesys_lock);

  f = filesys_open(file);
  if(f == NULL){
    lock_release(&filesys_lock);
    return -1;
  }
  else
  {
    int result;
    if(t != NULL)
    {
      //printf("thread name : %s",t->name);
      file_deny_write(f);
    }
    current->fd_table[current->fd_ref] = f;
    result = current->fd_ref;
    (current->fd_ref)++;
    lock_release(&filesys_lock);
    return result;
  }
}

void exit(int status)
{
  struct thread * cur = thread_current();
  int i = 0;
  printf("%s: exit(%d)\n", cur->name, status);

  sema_down(&(cur->child_sema));
  if( cur == cur->parent->child_for_waiting)
  {
    cur->parent->child_exit_status = status;
    cur->parent->child_exit_status_buffer[cur->child_index] = status;
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


  //sema_up(&cur->parent->child_sema);
  list_remove(&cur->child_elem);
  thread_exit();
}



int write (int fd, const void *buffer, unsigned size)
{
  lock_acquire(&filesys_lock);
  int result;
  if(fd == 1)
  {

    putbuf(buffer, size);

    int len = strlen(buffer);
    lock_release(&filesys_lock);
    return len < size ? len : size;
  }
  else if( ! (fd > 1 && fd < thread_current()->fd_ref)  )
  {
  lock_release(&filesys_lock);
    exit(-1);
  }
  else
  {

    if(buffer >=  0xC0000000)
    {
    lock_release(&filesys_lock);
      exit(-1);
    }

    void * addr = pagedir_get_page( thread_current()->pagedir, buffer);
    if(addr == NULL)
    {
    lock_release(&filesys_lock);
      exit(-1);
    }

    struct thread * current = thread_current();
    struct file * f =current->fd_table[fd];
    if(f != NULL)
    {

      if(f->deny_write == true)
      {
        file_deny_write(f);
      }

      result = file_write(f,buffer,size);
      lock_release(&filesys_lock);
      return result;
    }
    else
    {
      lock_release(&filesys_lock);
      exit(-1);
    }
  }
}

int exec( char * cmd_line)
{
  int result;
  struct thread * child;
  struct thread * current = thread_current();
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
 /*
 printf("cur name :%s\n",thread_current()->name);
 printf("local_cmd_line :  %s\n",local_cmd_line);
 printf("check_file  :  %p\n",check_file);
 */
 //thread_all_name_print();

 struct file * check_file = filesys_open(local_cmd_line);

  if(check_file == NULL)
  {
    check_file = get_thread_execute_file_with_name(local_cmd_line);
    if(check_file == NULL )
    {
        return -1;
    }
    else
    {
      file_close(check_file);
    }
  }
  else{
    file_close(check_file);
  }
  /*
  strlcpy(cur->child_execute_file[cur->child_index_count].name,local_cmd_line , 15);
  cur->child_execute_file[cur->child_index_count].exe_file = check_file;
  */
  strlcpy(current->cef[current->child_index_count].name, local_cmd_line,15);
  current->cef[current->child_index_count].exe_file = check_file;

  lock_acquire(&exe_lock);
  result = process_execute(cmd_line);
  lock_release(&exe_lock);
  return result;
}

int wait(tid_t tid)
{
  return process_wait(tid);
}
