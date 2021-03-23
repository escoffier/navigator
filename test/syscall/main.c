#include <unistd.h>
#include <sys/syscall.h>
int main(void) {
  syscall(SYS_accept, 1, NULL, NULL);
  syscall(SYS_accept4, 1, NULL, NULL, 0);
  syscall(SYS_acct, "SOME_FILE");
  syscall(SYS_add_key, "TYPE", "DESCRIPTION", NULL, 0, 0);
  syscall(SYS_adjtimex, NULL);
  syscall(SYS_bpf, 0, NULL, 0);
  syscall(SYS_delete_module, "NAME", 0);
  syscall(SYS_clock_adjtime, 0, 0);
  syscall(SYS_faccessat, 0, "PATH", 0, 0);
  syscall(SYS_fdatasync, 0);
  syscall(SYS_fsync, 0);
  syscall(SYS_fsetxattr, 0, "PATH", NULL, 0, 0);
  syscall(SYS_lsetxattr, 0, "PATH", NULL, 0, 0);
  syscall(SYS_setxattr, 0, "PATH", NULL, 0, 0);
  syscall(SYS_fstat, 0, NULL);
  syscall(SYS_mount, "SOURCE", "TARGET", "ftype", 0, NULL);
  syscall(SYS_nfsservctl, 0, NULL, NULL);
  //syscall(SYS_write, 1, "hello, world!\n", 14);
  return 0;
}
