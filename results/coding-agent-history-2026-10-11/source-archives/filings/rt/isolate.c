/* unshare creates user, mount, network and PID namespaces before this launcher. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
static void fail(void) { _exit(125); }
static void dir(const char *p) { if (mkdir(p,0755) && errno!=EEXIST) fail(); }
static void file(const char *p) { int f=open(p,O_CREAT|O_WRONLY,0644); if(f<0)fail(); close(f); }
static void readonly(const char *src,const char *dst) {
    if(mount(src,dst,NULL,MS_BIND|MS_REC,NULL))fail();
    if(mount(NULL,dst,NULL,MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV,NULL))fail();
}
int main(int argc,char **argv) {
    if(argc!=5)fail(); /* root, bundle, worker, RAM */
    if(mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL))fail();
    if(mount("tmpfs",argv[1],"tmpfs",MS_NOSUID|MS_NODEV,"size=4m,mode=755"))fail();
    if(chdir(argv[1]))fail();
    dir("usr");dir("bundle");dir("tmp");dir("home");dir("dev");dir("etc");
    if(symlink("usr/lib","lib")||symlink("usr/lib64","lib64")||symlink("usr/bin","bin"))fail();
    readonly("/usr","usr");readonly(argv[2],"bundle");
    file("worker.py");readonly(argv[3],"worker.py");
    file("dev/null");if(mount("/dev/null","dev/null",NULL,MS_BIND,NULL))fail();
    if(mount("tmpfs","tmp","tmpfs",MS_NOSUID|MS_NODEV|MS_NOEXEC,"size=64m,mode=700"))fail();
    if(chroot(".")||chdir("/tmp"))fail();
    if(mount(NULL,"/",NULL,MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV,NULL))fail();
    struct __user_cap_header_struct header={_LINUX_CAPABILITY_VERSION_3,0};
    struct __user_cap_data_struct data[2]={{0},{0}};
    if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)||prctl(PR_SET_DUMPABLE,0,0,0,0)||syscall(SYS_capset,&header,&data))fail();
    execl("/usr/bin/python3","python3","-I","-B","/worker.py","/bundle","/tmp",argv[4],(char*)NULL);
    fail();
}
