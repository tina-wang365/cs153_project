#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "lib/user/syscall.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "devices/shutdown.h" 
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"

#define USER_VADDR_BOTTOM (void *) 0x08048000

static void syscall_handler (struct intr_frame *);

/* Creates a lock that can be used by a filesys operations */
struct lock fs_lock; 

struct file * get_file(int fd UNUSED);
void grab_stack_args(struct intr_frame * f, int * arg, int num_args);

struct p_file {
    struct file *file;
    int fd;
    struct list_elem elem;
};

void validate_ptr (const void *vaddr); 
void validate_buf (void *buf, unsigned size);
int user_to_kernel_ptr(const void *vaddr);
int add_file(struct file * f);
void p_close_file(int fd);
pid_t exec (const char *file);

void
syscall_init (void) 
{
  lock_init(&fs_lock); /* MINE */
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int argv[3]; /* MINE */
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
        grab_stack_args(f, &argv[0], 1);
        argv[0] = user_to_kernel_ptr((const void *) argv[0]);
        f->eax = exec((const char *) argv[0]);
        break;
    }
    case SYS_WAIT: {
        grab_stack_args(f, &argv[0], 1);
        f->eax = wait(argv[0]);
        break;
    }
    case SYS_CREATE: {
        grab_stack_args(f, &argv[0], 2);
        argv[0] = user_to_kernel_ptr((const void *) argv[0]);
        f->eax = create((const char *) argv[0], (unsigned)argv[1]);
        break;
    }
    case SYS_REMOVE: {
        grab_stack_args(f, &argv[0], 1);
        argv[0] = user_to_kernel_ptr((const void *) argv[0]);
        f->eax = remove((const char *) argv[0]);
        break;
    }
    case SYS_OPEN: {
        grab_stack_args(f, &argv[0], 1);
        argv[0] = user_to_kernel_ptr((const void *) argv[0]);
        f->eax = open((const char *) argv[0]); 
        break;
    }
    case SYS_FILESIZE: {
        grab_stack_args(f, &argv[0], 1);
        f->eax = filesize(argv[0]); 
        break;
    }
    case SYS_READ: {
        grab_stack_args(f, &argv[0], 3);
        validate_buf((void *) argv[1], (unsigned) argv[2]);
        argv[1] = user_to_kernel_ptr((void *) argv[1]);
        f->eax = read(argv[0], (void *) argv[1], (unsigned)argv[2]);  
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
        grab_stack_args(f, &argv[0], 2);
        seek(argv[0], (unsigned) argv[1]);       
        break;
    }
    case SYS_TELL: {
        grab_stack_args(f, &argv[0], 1);
        f->eax = tell((int) argv[0]);
        break;
    }
    case SYS_CLOSE: {
       grab_stack_args(f, &argv[0], 1);
        close(argv[0]); 
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

pid_t exec (const char *file) {
    return process_execute(file);
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

/* Gets a file from the list using the given file descriptor */
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

/* Adds the given file to the file_list of the current thread. It also 
 * updates the file descriptor */
int add_file(struct file * f)
{
    struct p_file *pf = malloc(sizeof(struct p_file));
    pf->file = f;
    pf->fd = thread_current()->fd;
    thread_current()->fd += 1;
    list_push_back(&thread_current()->file_list, &pf->elem);
    return pf->fd;
}

/* Iterates through the file list of the current thread. 
 * If the file descriptor (fd) is found, close it. 
 * It is also removed from the file list */
void p_close_file(int fd)
{
    struct thread * t = thread_current();
    struct list_elem * e;
    for(e = list_begin(&t->file_list); e != list_end(&t->file_list); e = list_next(e))
    {
        struct p_file *pf = list_entry(e, struct p_file, elem);
        if(fd == pf->fd || fd == -1) //all closed files
        {
            file_close(pf->file);
            list_remove(&pf->elem);
            free(pf);
            if( fd != -1) {
                return;
            }
        }
    }
}
int write (int fd, const void *buffer, unsigned length) {
    /* File descriptor for std out */
    if(fd == STDOUT_FILENO)
    {
        putbuf(buffer, length);
        return length;
    }
    /* Write the contents of the buffer to file_to_write */
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

int filesize (int fd)
{
    lock_acquire(&fs_lock);
    struct file * f_temp = get_file(fd);
    if(f_temp == NULL)
    {
        lock_release(&fs_lock);
        return -1;
    }
    int size = file_length(f_temp);
    lock_release(&fs_lock);
    return size;
}

int read (int fd, void * buffer, unsigned size)
{
    if(fd == STDIN_FILENO)
    {
        unsigned index;
        uint8_t* buf_temp = (uint8_t *) buffer;
        for(index = 0; index < size; ++index)
        {
            buf_temp[index] = input_getc();
        }
        return size;
    } 
    lock_acquire(&fs_lock);
    struct file * f_temp = get_file(fd);
    
    if(f_temp == NULL)
    {
        lock_release(&fs_lock);
        return -1;
    }
    int bytes = file_read(f_temp, buffer, size);
    lock_release(&fs_lock);
    return bytes;
}

/* Gets the arguments needed off the stack */
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

/* Checks that the virtual address is valid and in the appropriate range
 * inside the virtual memory */
void validate_ptr (const void *vaddr) {
    if (!is_user_vaddr(vaddr) || (vaddr < USER_VADDR_BOTTOM)) {
        exit(-1);
    }
}

/* For each item in the buffer, it calls validate_ptr() to check the
 * virtual address */
void validate_buf (void *buf, unsigned size) {
    unsigned i;
    void *local_buf = (void *) buf;
    for (i = 0; i < size; ++i) {
        validate_ptr((const void*) local_buf);
        local_buf++;
    }
}

bool create (const char *file, unsigned initial_size) {
    lock_acquire(&fs_lock);
    bool status = filesys_create(file, initial_size);
    lock_release(&fs_lock);
    return status;
}

bool remove (const char *file) {
    lock_acquire(&fs_lock);
    bool status = filesys_remove(file);
    lock_release(&fs_lock);
    return status;
}

int open(const char * file)
{
    lock_acquire(&fs_lock);
    struct file * f_tmp = filesys_open(file);
    if(f_tmp == NULL)
    {
        lock_release(&fs_lock);
        return -1;
    }
    int fd = add_file(f_tmp);
    lock_release(&fs_lock);
  
    return fd;
}

void close(int fd)
{
    lock_acquire(&fs_lock);
    p_close_file(fd);
    lock_release(&fs_lock);
}

void seek(int fd, unsigned position)
{
    lock_acquire(&fs_lock);
    struct file * f_temp = get_file(fd);
    if(f_temp == NULL)
    {
        lock_release(&fs_lock);
        return;
    }

    file_seek(f_temp, position);
    lock_release(&fs_lock);
    return;

}

unsigned tell(int fd)
{
    lock_acquire(&fs_lock);
    struct file * f_temp = get_file(fd);
    if(f_temp == NULL)
    {
        lock_release(&fs_lock);
        return -1;
    }
    off_t offset = file_tell(f_temp);
    lock_release(&fs_lock);
    return offset;
}
