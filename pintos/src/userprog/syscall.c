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
#include "userprog/process.h"
#include "userprog/pagedir.h"

static void syscall_handler (struct intr_frame *);
struct lock fs_lock;

struct file * get_file(int fd UNUSED);
void grab_stack_args(struct intr_frame * f, int * arg, int num_args);
#define USER_VADDR_BOTTOM (void *) 0x08048000

struct p_file {
    struct file *file;
    int fd;
    struct list_elem elem;
};

void validate_ptr (const void *vaddr); 
void validate_buf (void *buf, unsigned size);
int user_to_kernel_ptr(const void *vaddr);
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
  //validate_ptr((const void*)f->esp);
  switch ( * (int*) f->esp ) 
  {
    case SYS_HALT: {
        halt();
        break;
    }
    case SYS_EXIT: {
        grab_stack_args(f, &argv[0], 1);
        exit(argv[0]);
        break;
    }
    case SYS_EXEC: {
        break;
    }
    case SYS_WAIT: {
        grab_stack_args(f, &argv[0], 1);
        f->eax = wait(argv[0]);
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
        grab_stack_args(f, &argv[0], 3);
        validate_buf((void *) argv[1], (unsigned) argv[2]);
        argv[1] = user_to_kernel_ptr((const void *) argv[1]);
        f->eax = write(argv[0], (const void *) argv[1], (unsigned)argv[2]);
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
    printf("%s: exit(%d)\n", thread_current()->name, status);
    thread_exit();
}

int wait (pid_t pid) {
    return process_wait(pid);
}

int user_to_kernel_ptr(const void *vaddr) {
    validate_ptr(vaddr);

    void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);

    if (!ptr) {
        exit(-1);
    }
    return (int) ptr;
}

struct file * get_file(int fd)
{
    struct thread *t = thread_current();
    struct list_elem *e;
    
    for (e = list_begin(&t->file_list); e != list_end(&t->file_list);
         e = list_next(e)) 
    {   
        struct p_file *pf = list_entry(e, struct p_file, elem);
        if (fd == pf->fd)
            return pf->file;
    }
    return NULL;
}

int write (int fd, const void *buffer, unsigned length) {

/*    lock_acquire(&fs_lock);
    if (fd == STDOUT_FILENO) {
        int i;
        int buf_size = 256;
        for ( i = length/buf_size; i > 0; --i ) {
            putbuf(buffer,length);
            return length;
        }
    } */

    if(fd == STDOUT_FILENO)
    {
        putbuf(buffer, length);
        return length;
    }
    lock_acquire(&fs_lock);

    struct file * file_to_write = get_file(fd);
    if (!file_to_write) {
        lock_release(&fs_lock);
        return -1;
    }
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
        validate_ptr((const void *) ptr);
        arg[index] = *ptr;
    }
}

void validate_ptr (const void *vaddr) {
    if (!is_user_vaddr(vaddr) || (vaddr < USER_VADDR_BOTTOM) /*vaddr < (void*)0x08048000*/) {
        exit(-1);
    }
}

void validate_buf (void *buf, unsigned size) {
    unsigned i;
    void *local_buf = (void *) buf;
    for (i = 0; i < size; ++i) {
        validate_ptr((const void*) local_buf);
        local_buf++;
    }
}

