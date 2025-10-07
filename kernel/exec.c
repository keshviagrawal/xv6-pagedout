#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "elf.h"

// ***** REMOVED *****
// static int loadseg(pde_t *, uint64, struct inode *, uint, uint);
// ************

// map ELF permissions to PTE permission bits.
int flags2perm(int flags)
{
    int perm = 0;
    if(flags & 0x1)
      perm = PTE_X;
    if(flags & 0x2)
      perm |= PTE_W;
    return perm;
}

//
// the implementation of the exec() system call
//
int
kexec(char *path, char **argv)
{
  char *s, *last;
  int i, off;
  uint64 argc, sz = 0, sp, ustack[MAXARG], stackbase;
  struct elfhdr elf;
  struct inode *ip;
  struct proghdr ph;
  pagetable_t pagetable = 0, oldpagetable;
  struct proc *p = myproc();
  
  // ***** ADDED *****
  // These will hold the new process's properties until we commit them.
  struct exec_segment segments[MAX_EXEC_SEGS];
  int num_segments = 0;
  struct inode *new_exec_ip = 0;
  // ************

  begin_op();

  // Open the executable file.
  if((ip = namei(path)) == 0){
    end_op();
    return -1;
  }
  ilock(ip);

  // Read the ELF header.
  if(readi(ip, 0, (uint64)&elf, 0, sizeof(elf)) != sizeof(elf))
    goto bad;

  // Is this really an ELF file?
  if(elf.magic != ELF_MAGIC)
    goto bad;

  if((pagetable = proc_pagetable(p)) == 0)
    goto bad;

  // ***** ADDED and changed few things *****
  // For demand paging, we don't load segments now.
  // We just record the information for on-demand loading.
  for(i=0, off=elf.phoff; i<elf.phnum; i++, off+=sizeof(ph)){
    if(readi(ip, 0, (uint64)&ph, off, sizeof(ph)) != sizeof(ph))
      goto bad;
    if(ph.type != ELF_PROG_LOAD)
      continue;
    if(ph.memsz < ph.filesz)
      goto bad;
    if(ph.vaddr + ph.memsz < ph.vaddr)
      goto bad;
    if(ph.vaddr % PGSIZE != 0)
      goto bad;
    if(num_segments >= MAX_EXEC_SEGS)
      goto bad;
    segments[num_segments].va = ph.vaddr;
    segments[num_segments].memsz = ph.memsz;
    segments[num_segments].filesz = ph.filesz;
    segments[num_segments].offset = ph.off;
    segments[num_segments].perm = flags2perm(ph.flags);
    num_segments++;
    if(ph.vaddr + ph.memsz > sz)
      sz = ph.vaddr + ph.memsz;
  }
  new_exec_ip = idup(ip);
  // ************
  
  iunlockput(ip);
  end_op();
  ip = 0;

  p = myproc();
  uint64 oldsz = p->sz;
  struct inode *old_exec_ip = p->exec_ip;

  // ***** ADDED and changed few things *****
  // For demand paging, we just reserve the address space for the stack.
  // It will be allocated on a page fault.
  sz = PGROUNDUP(sz);
  sz += (USERSTACK + 1) * PGSIZE;
  sp = sz;
  stackbase = sp - USERSTACK*PGSIZE;
  p->in_exec = 1; // Signal that we are in exec
  // ************

  // Copy argument strings into new stack, remember their
  // addresses in ustack[].
  for(argc = 0; argv[argc]; argc++) {
    if(argc >= MAXARG)
      goto bad;
    sp -= strlen(argv[argc]) + 1;
    sp -= sp % 16; // riscv sp must be 16-byte aligned
    if(sp < stackbase)
      goto bad;
    if(copyout(pagetable, sp, argv[argc], strlen(argv[argc]) + 1) < 0)
      goto bad;
    ustack[argc] = sp;
  }
  ustack[argc] = 0;

  // push a copy of ustack[], the array of argv[] pointers.
  sp -= (argc+1) * sizeof(uint64);
  sp -= sp % 16;
  if(sp < stackbase)
    goto bad;
  if(copyout(pagetable, sp, (char *)ustack, (argc+1)*sizeof(uint64)) < 0)
    goto bad;

  // ***** ADDED *****
  p->in_exec = 0; // End of exec-specific fault handling
  // ************

  // a0 and a1 contain arguments to user main(argc, argv)
  // argc is returned via the system call return
  // value, which goes in a0.
  p->trapframe->a1 = sp;

  // Save program name for debugging.
  for(last=s=path; *s; s++)
    if(*s == '/')
      last = s+1;
  safestrcpy(p->name, last, sizeof(p->name));
    
  // Commit to the user image.
  oldpagetable = p->pagetable;
  p->pagetable = pagetable;
  p->sz = sz;
  p->trapframe->epc = elf.entry;  // initial program counter = ulib.c:start()
  p->trapframe->sp = sp; // initial stack pointer
  // ***** ADDED *****
  p->exec_ip = new_exec_ip;
  p->num_exec_segments = num_segments;
  memmove(p->exec_segments, segments, sizeof(segments));
  // ************
  proc_freepagetable(oldpagetable, oldsz);
  if(old_exec_ip)
    iput(old_exec_ip);

  return argc; // this ends up in a0, the first argument to main(argc, argv)

 bad:
  p->in_exec = 0;
  if(pagetable)
    proc_freepagetable(pagetable, sz);
  if(new_exec_ip)
    iput(new_exec_ip);
  if(ip){
    iunlockput(ip);
    end_op();
  }
  return -1;
}


// basically it has been modified in such a way that it no longer load the entire program into memory at once. Instead, it sets up the necessary info for pages to be loaded on demand when a page fault occurs