#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
/* MINE */
#include "devices/shutdown.h" 
#include "lib/user/syscall.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
//#include "userprog/pagedir.h"
//#include "userprog/process.h"
static void syscall_handler (struct intr_frame *);
struct lock fs_lock;

#define USER_VADDR_BOTTOM (void *) 0x08084000

/* END MINE */
void
syscall_init (void) 
{
  lock_init(&fs_lock); //mine
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
   int argv[3]; //mine
  switch ( (int) f->esp ) 
  {
    case SYS_HALT: {
        halt();
        break;
    }
    case SYS_EXIT: {
        break;
    }
    case SYS_EXEC: {
        break;
    }
    case SYS_WAIT: {
        break;
    }
    case SYS_CREATE: {
        break;
    }
    case SYS_REMOVE: {
        break;
    }
    case SYS_OPEN: {
        break;
    }
    case SYS_FILESIZE: {
        break;
    }
    case SYS_READ: {
        break;
    }
    case SYS_WRITE: {
        printf("ARG0: %d\n", argv[0]);
        printf("ARG1: %d\n", argv[1]);
        printf("ARG2: %d\n", argv[2]);
        printf("ARG3: %d\n", argv[3]); 

        
        grab_stack_args(f, argv, 3);
        write(argv[1], (const void *) argv[2], (unsigned)argv[3]);
               
        break;
    }
    case SYS_SEEK: {
        break;
    }
    case SYS_TELL: {
        break;
    }
    case SYS_CLOSE: {
        break;
    }
  }
}

void halt (void) {
    shutdown_power_off();
}

void exit (int status) {
    struct thread * t = thread_current();
    t->status = status;
    printf("Exit status: %d", status);
    thread_exit();
}

struct file * get_file(int fd)
{
    return NULL;
}
int write (int fd, const void *buffer, unsigned length) {
    if(fd == STDOUT_FILENO)
    {
        putbuf(buffer, (size_t)length);
        return (int)length;
    }
    lock_acquire(&fs_lock);
    struct file * file_to_write = get_file(fd);
    int bytes = file_write(file_to_write, buffer, length);
    lock_release(&fs_lock);
    return bytes;    
}

void grab_stack_args(struct intr_frame * f, int * arg, int num_args)
{
    int index;
    int * ptr;
    for(index = 0; index < num_args; ++index)
    {
        ptr = (int *) f->esp + index + 1;
        //validate_ptr((const void *) ptr);
        arg[index] = *ptr;
    }
}

