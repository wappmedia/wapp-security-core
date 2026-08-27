#define _GNU_SOURCE
#include <stdio.h>

#if !defined(__linux__) || !defined(__x86_64__)
int main(void) {
    fputs("wapp-native-displaced-inventory: unsupported platform\n", stderr);
    return 78;
}
#else

#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <stdarg.h>
#include <stddef.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef O_NOATIME
#define O_NOATIME 01000000
#endif
#ifndef O_PATH
#define O_PATH 010000000
#endif
#ifndef ST_NOATIME
#define ST_NOATIME 0x0400
#endif
#ifndef ST_RDONLY
#define ST_RDONLY 0x0001
#endif

#ifndef WAPP_NATIVE_MAX_SECONDS
#define WAPP_NATIVE_MAX_SECONDS 900
#endif

enum {
    ENTRY_CAP = 200000,
    DIRECTORY_CAP = 50000,
    FILE_CAP = 150000,
    DEPTH_CAP = 64,
    MAX_RELATIVE_BYTES = 4096,
    MAX_SECONDS = WAPP_NATIVE_MAX_SECONDS,
    IO_CHUNK = 1024 * 1024,
    /* Relative + absolute + symlink-target hex and fixed metadata stay bounded. */
    DIAGNOSTIC_LINE_CAP = MAX_RELATIVE_BYTES * 9 + 4096,
};
static const uint64_t MAX_FILE_BYTES = 1024ULL * 1024ULL * 1024ULL;
static const uint64_t MAX_TOTAL_BYTES = 32ULL * 1024ULL * 1024ULL * 1024ULL;
static const size_t MAX_OUTPUT_BYTES = 120ULL * 1024ULL * 1024ULL;
static const size_t MAX_ROLLBACK_BYTES = 16ULL * 1024ULL * 1024ULL;
static const char *RUNTIME_MODE = "PRODUCTION_RELEASE_PINNED_NATIVE_LINUX_X86_64_MEMFD_V1";
static const char *RUNTIME_PATH = "memfd:wapp-native-displaced-inventory-linux-x86_64-v1";

typedef struct { uint32_t h[8]; uint64_t bits; unsigned char block[64]; size_t used; } Sha256;
static const uint32_t K[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
static uint32_t rotr(uint32_t x, unsigned n){ return (x>>n)|(x<<(32-n)); }
static void sha_block(Sha256 *s,const unsigned char *p){
  uint32_t w[64],a,b,c,d,e,f,g,h,t1,t2; unsigned i;
  for(i=0;i<16;i++) w[i]=((uint32_t)p[i*4]<<24)|((uint32_t)p[i*4+1]<<16)|((uint32_t)p[i*4+2]<<8)|p[i*4+3];
  for(i=16;i<64;i++){uint32_t x=w[i-15],y=w[i-2];w[i]=(rotr(y,17)^rotr(y,19)^(y>>10))+w[i-7]+(rotr(x,7)^rotr(x,18)^(x>>3))+w[i-16];}
  a=s->h[0];b=s->h[1];c=s->h[2];d=s->h[3];e=s->h[4];f=s->h[5];g=s->h[6];h=s->h[7];
  for(i=0;i<64;i++){t1=h+(rotr(e,6)^rotr(e,11)^rotr(e,25))+((e&f)^((~e)&g))+K[i]+w[i];t2=(rotr(a,2)^rotr(a,13)^rotr(a,22))+((a&b)^(a&c)^(b&c));h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;}
  s->h[0]+=a;s->h[1]+=b;s->h[2]+=c;s->h[3]+=d;s->h[4]+=e;s->h[5]+=f;s->h[6]+=g;s->h[7]+=h;
}
static void sha_init(Sha256 *s){static const uint32_t H[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};memcpy(s->h,H,sizeof H);s->bits=0;s->used=0;}
static void sha_update(Sha256 *s,const void *vp,size_t n){const unsigned char *p=vp;s->bits+=(uint64_t)n*8;while(n){size_t take=64-s->used;if(take>n)take=n;memcpy(s->block+s->used,p,take);s->used+=take;p+=take;n-=take;if(s->used==64){sha_block(s,s->block);s->used=0;}}}
static void sha_final(Sha256 *s,unsigned char out[32]){unsigned i;s->block[s->used++]=0x80;if(s->used>56){while(s->used<64)s->block[s->used++]=0;sha_block(s,s->block);s->used=0;}while(s->used<56)s->block[s->used++]=0;for(i=0;i<8;i++)s->block[63-i]=(unsigned char)(s->bits>>(8*i));sha_block(s,s->block);for(i=0;i<8;i++){out[i*4]=(unsigned char)(s->h[i]>>24);out[i*4+1]=(unsigned char)(s->h[i]>>16);out[i*4+2]=(unsigned char)(s->h[i]>>8);out[i*4+3]=(unsigned char)s->h[i];}}
static void hex32(const unsigned char in[32],char out[65]){static const char H[]="0123456789abcdef";for(int i=0;i<32;i++){out[i*2]=H[in[i]>>4];out[i*2+1]=H[in[i]&15];}out[64]=0;}
static void digest(const void *p,size_t n,char out[65]){Sha256 s;unsigned char b[32];sha_init(&s);sha_update(&s,p,n);sha_final(&s,b);hex32(b,out);}

typedef struct { char **v; size_t n,cap,bytes; } Lines;
typedef struct { unsigned char *v; size_t n; } Bytes;
typedef struct { dev_t dev; ino_t ino; } Identity;
typedef struct { Identity *v; size_t n,cap; } Identities;
typedef struct { char *storage; char *field[16]; } DiagnosticEntry;
typedef struct { const char *cursor; char previous[DIAGNOSTIC_LINE_CAP]; size_t count; } DiagnosticCursor;
typedef struct { char storage[DIAGNOSTIC_LINE_CAP]; char *field[16]; } DiagnosticRecord;
typedef struct { char behavior; char *path; int present,observed; } VolatileRule;
typedef struct { VolatileRule v[64]; size_t n; } VolatilePolicy;
static int nibble(char c);
static unsigned char *decode_hex(const char *text,size_t *outn);
static int valid_sha(const char *s);
typedef struct {
  Lines rows,issues; Identities dirs; size_t entries,dirs_n,files,hashed,uploads,other;
  uint64_t hashed_bytes; int stopped; time_t deadline; const char *requested_root; const char *runtime_sha; const char *runtime_identity;
} Snapshot;

static void die(const char *m){fprintf(stderr,"wapp-native-displaced-inventory: %s\n",m);exit(20);}
static void alarm_exit(int unused){
  static const char message[]="wapp-native-displaced-inventory: hard time cap exceeded\n";
  (void)unused;
  ssize_t written=write(STDERR_FILENO,message,sizeof(message)-1);
  (void)written;
  _exit(124);
}
static void apply_process_limits(void){struct rlimit memory={256ULL*1024ULL*1024ULL,256ULL*1024ULL*1024ULL},cpu={MAX_SECONDS+5,MAX_SECONDS+5},files={64,64};if(setrlimit(RLIMIT_AS,&memory)<0||setrlimit(RLIMIT_CPU,&cpu)<0||setrlimit(RLIMIT_NOFILE,&files)<0)die("process limits unavailable");signal(SIGALRM,alarm_exit);alarm(MAX_SECONDS);}
static void *xmalloc(size_t n){void *p=malloc(n?n:1);if(!p)die("memory cap/allocation failure");return p;}
static void check_deadline(Snapshot *s){if(time(NULL)>s->deadline)die("hard time cap exceeded");}
static int cmpstr(const void *a,const void *b){return strcmp(*(char *const*)a,*(char *const*)b);}
static int cmpbytes(const void *a,const void *b){const Bytes *x=a,*y=b;size_t m=x->n<y->n?x->n:y->n;int c=memcmp(x->v,y->v,m);return c?c:(x->n>y->n)-(x->n<y->n);}
static void lines_add(Lines *l,char *value){size_t n=strlen(value)+1;if(l->bytes+n>MAX_OUTPUT_BYTES)die("output byte cap exceeded");if(l->n==l->cap){size_t c=l->cap?l->cap*2:256;if(c>ENTRY_CAP*3ULL)c=ENTRY_CAP*3ULL;if(c<=l->cap)die("line cap");l->v=realloc(l->v,c*sizeof(*l->v));if(!l->v)die("memory cap/allocation failure");l->cap=c;}l->v[l->n++]=value;l->bytes+=n;}
static void lines_free(Lines *l){for(size_t i=0;i<l->n;i++)free(l->v[i]);free(l->v);memset(l,0,sizeof *l);}
static char *hex_bytes(const unsigned char *p,size_t n){static const char H[]="0123456789abcdef";if(n>(SIZE_MAX-1)/2)die("hex overflow");char *o=xmalloc(n*2+1);for(size_t i=0;i<n;i++){o[i*2]=H[p[i]>>4];o[i*2+1]=H[p[i]&15];}o[n*2]=0;return o;}
static char *fmt_alloc(const char *fmt,...){va_list ap,cp;va_start(ap,fmt);va_copy(cp,ap);int n=vsnprintf(NULL,0,fmt,cp);va_end(cp);if(n<0)die("serialization failure");char *p=xmalloc((size_t)n+1);vsnprintf(p,(size_t)n+1,fmt,ap);va_end(ap);return p;}
static long long ns_time(struct timespec ts){return (long long)ts.tv_sec*1000000000LL+ts.tv_nsec;}
static int same_stat(const struct stat *a,const struct stat *b){return a->st_dev==b->st_dev&&a->st_ino==b->st_ino&&a->st_mode==b->st_mode&&a->st_nlink==b->st_nlink&&a->st_uid==b->st_uid&&a->st_gid==b->st_gid&&a->st_rdev==b->st_rdev&&a->st_size==b->st_size&&a->st_blocks==b->st_blocks&&ns_time(a->st_mtim)==ns_time(b->st_mtim)&&ns_time(a->st_ctim)==ns_time(b->st_ctim);}
static const char *kind(mode_t m){if(S_ISREG(m))return "REGULAR";if(S_ISDIR(m))return "DIRECTORY";if(S_ISLNK(m))return "SYMLINK";if(S_ISBLK(m))return "BLOCK_DEVICE";if(S_ISCHR(m))return "CHAR_DEVICE";if(S_ISFIFO(m))return "FIFO";if(S_ISSOCK(m))return "SOCKET";return "OTHER";}
static int is_safe_component(const unsigned char *p,size_t n){return n&&!(n==1&&p[0]=='.')&&!(n==2&&p[0]=='.'&&p[1]=='.')&&!memchr(p,'/',n)&&!memchr(p,0,n);}
static int open_component(int dirfd,const char *name,int flags,int *used_openat2){
  struct open_how how={.flags=(uint64_t)flags,.resolve=RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_SYMLINKS};
  int fd=(int)syscall(SYS_openat2,dirfd,name,&how,sizeof how);
  if(fd>=0){*used_openat2=1;return fd;}
  if(errno!=ENOSYS&&errno!=EINVAL&&errno!=E2BIG)return -1;
  fd=openat(dirfd,name,flags);if(fd>=0){struct stat st;if(fstat(fd,&st)<0){close(fd);return -1;}*used_openat2=0;}return fd;
}
static int open_root(const char *path,int *used_openat2){
  const char *p=path;if(*p!='/')die("invalid physical root");int fd=open("/",O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(fd<0)die("root descriptor unavailable");p++;
  while(*p){const char *slash=strchr(p,'/');size_t n=slash?(size_t)(slash-p):strlen(p);if(!is_safe_component((const unsigned char*)p,n)){close(fd);die("unsafe physical root component");}char name[256];if(n>=sizeof name){close(fd);die("physical root component cap");}memcpy(name,p,n);name[n]=0;int final=!slash;int flags=final?(O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_NOATIME|O_CLOEXEC):(O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);int nfd=open_component(fd,name,flags,used_openat2);if(nfd<0){close(fd);die(final?"atime-safe root open unavailable":"root traversal failed");}close(fd);fd=nfd;if(final)break;p=slash+1;}
  return fd;
}
static void id_add(Snapshot *s,dev_t d,ino_t i){for(size_t x=0;x<s->dirs.n;x++)if(s->dirs.v[x].dev==d&&s->dirs.v[x].ino==i){return;}if(s->dirs.n==s->dirs.cap){size_t c=s->dirs.cap?s->dirs.cap*2:256;s->dirs.v=realloc(s->dirs.v,c*sizeof(*s->dirs.v));if(!s->dirs.v)die("identity allocation");s->dirs.cap=c;}s->dirs.v[s->dirs.n++]=(Identity){d,i};}
static int id_seen(Snapshot *s,dev_t d,ino_t i){for(size_t x=0;x<s->dirs.n;x++)if(s->dirs.v[x].dev==d&&s->dirs.v[x].ino==i)return 1;return 0;}
static void issue(Snapshot *s,const char *reason,const unsigned char *rel,size_t rn,const char *detail){char h[65];digest(detail,strlen(detail),h);char *rh=hex_bytes(rel,rn);lines_add(&s->issues,fmt_alloc("UNRESOLVED\t%s\t%s\t%s",reason,rh,h));free(rh);}

struct linux_dirent64_local { uint64_t d_ino; int64_t d_off; unsigned short d_reclen; unsigned char d_type; char d_name[]; };
static int read_names(Snapshot *s,int fd,const unsigned char *rel,size_t rn,Bytes **out,size_t *outn){
  int dupfd=dup(fd);if(dupfd<0){issue(s,"DIRECTORY_READ_UNRESOLVED",rel,rn,"dup");return -1;}if(lseek(dupfd,0,SEEK_SET)<0){close(dupfd);issue(s,"DIRECTORY_READ_UNRESOLVED",rel,rn,"seek");return -1;}
  Bytes *names=NULL;size_t n=0,cap=0;char buf[32768];
  /* Each listing verifies the same directory contents; it does not consume
     the traversal's global entry budget a second time. */
  for(;;){check_deadline(s);int got=(int)syscall(SYS_getdents64,dupfd,buf,sizeof buf);if(got<0){close(dupfd);issue(s,"DIRECTORY_READ_UNRESOLVED",rel,rn,"getdents");goto bad;}if(got==0)break;for(int pos=0;pos<got;){struct linux_dirent64_local *d=(void*)(buf+pos);if(d->d_reclen<offsetof(struct linux_dirent64_local,d_name)+1||pos+d->d_reclen>got){close(dupfd);die("malformed getdents64");}size_t max=d->d_reclen-offsetof(struct linux_dirent64_local,d_name);size_t len=strnlen(d->d_name,max);if(len==max){close(dupfd);die("unterminated getdents64 name");}pos+=d->d_reclen;if((len==1&&d->d_name[0]=='.')||(len==2&&d->d_name[0]=='.'&&d->d_name[1]=='.'))continue;if(!is_safe_component((unsigned char*)d->d_name,len)){close(dupfd);issue(s,"UNSAFE_NAME_UNRESOLVED",rel,rn,"name");s->stopped=1;goto bad;}if(n>=ENTRY_CAP){close(dupfd);issue(s,"ENTRY_CAP",rel,rn,"entries");s->stopped=1;goto bad;}if(n==cap){size_t c=cap?cap*2:64;names=realloc(names,c*sizeof(*names));if(!names)die("name allocation");cap=c;}names[n].v=xmalloc(len);memcpy(names[n].v,d->d_name,len);names[n].n=len;n++;}}
  close(dupfd);
  qsort(names,n,sizeof *names,cmpbytes);*out=names;*outn=n;return 0;
bad:for(size_t i=0;i<n;i++)free(names[i].v);free(names);return -1;
}
static void names_free(Bytes *v,size_t n){for(size_t i=0;i<n;i++)free(v[i].v);free(v);}
static int names_equal(Bytes *a,size_t an,Bytes *b,size_t bn){if(an!=bn)return 0;for(size_t i=0;i<an;i++)if(a[i].n!=b[i].n||memcmp(a[i].v,b[i].v,a[i].n))return 0;return 1;}
static int has_uploads_component(const unsigned char *rel,size_t rn){size_t start=0;for(size_t i=0;i<=rn;i++)if(i==rn||rel[i]=='/'){if(i-start==7&&!memcmp(rel+start,"uploads",7))return 1;start=i+1;}return 0;}
static char *join_bytes(const unsigned char *a,size_t an,const unsigned char *b,size_t bn,int slash,size_t *outn){size_t n=an+(slash?1:0)+bn;unsigned char *p=xmalloc(n+1);memcpy(p,a,an);if(slash)p[an]='/';memcpy(p+an+slash,b,bn);p[n]=0;*outn=n;return (char*)p;}
static char *hash_regular(Snapshot *s,int parent,const char *name,const unsigned char *rel,size_t rn,const struct stat *before){
  uint64_t file_bytes=(uint64_t)before->st_size;
  if(file_bytes>MAX_FILE_BYTES){issue(s,"FILE_BYTE_CAP",rel,rn,"size");return strdup("-");}if(s->hashed_bytes>MAX_TOTAL_BYTES||file_bytes>MAX_TOTAL_BYTES-s->hashed_bytes){issue(s,"TOTAL_BYTE_CAP",rel,rn,"total");return strdup("-");}
  int used=0,fd=open_component(parent,name,O_RDONLY|O_NOFOLLOW|O_NOATIME|O_CLOEXEC,&used);if(fd<0){issue(s,"FILE_OPEN_UNRESOLVED",rel,rn,"open");return strdup("-");}struct stat opened,after,pathst;if(fstat(fd,&opened)<0||!same_stat(&opened,before)){close(fd);issue(s,"FILE_IDENTITY_RACE",rel,rn,"open");return strdup("-");}
  Sha256 sh;sha_init(&sh);unsigned char *buf=xmalloc(IO_CHUNK);uint64_t count=0;for(;;){check_deadline(s);ssize_t n=read(fd,buf,IO_CHUNK);if(n<0){free(buf);close(fd);issue(s,"FILE_READ_UNRESOLVED",rel,rn,"read");return strdup("-");}if(!n)break;count+=(uint64_t)n;if(count>(uint64_t)before->st_size){free(buf);close(fd);issue(s,"FILE_GROWTH_RACE",rel,rn,"growth");return strdup("-");}sha_update(&sh,buf,(size_t)n);}free(buf);if(fstat(fd,&after)<0||fstatat(parent,name,&pathst,AT_SYMLINK_NOFOLLOW)<0||count!=(uint64_t)before->st_size||!same_stat(&opened,&after)||!same_stat(&after,&pathst)){close(fd);issue(s,"FILE_IDENTITY_RACE",rel,rn,"read");return strdup("-");}close(fd);unsigned char d[32];char *out=xmalloc(65);sha_final(&sh,d);hex32(d,out);s->hashed++;s->hashed_bytes+=count;return out;
}
static char *symlink_target(Snapshot *s,int parent,const char *name,const unsigned char *rel,size_t rn,const struct stat *before){
  int fd=openat(parent,name,O_PATH|O_NOFOLLOW|O_CLOEXEC);if(fd<0){issue(s,"SYMLINK_TARGET_READ_UNRESOLVED",rel,rn,"open");return strdup("-");}struct stat opened,after,pathst;struct statfs fs;if(fstat(fd,&opened)<0||!same_stat(&opened,before)){close(fd);issue(s,"SYMLINK_IDENTITY_RACE",rel,rn,"open");return strdup("-");}if(fstatfs(fd,&fs)<0||!(fs.f_flags&(ST_RDONLY|ST_NOATIME))){close(fd);issue(s,"SYMLINK_TARGET_NOATIME_UNRESOLVED",rel,rn,"mount-flags");return strdup("-");}char buf[4097];ssize_t n=readlinkat(fd,"",buf,sizeof(buf)-1);if(n<0||n>4096){close(fd);issue(s,"SYMLINK_TARGET_READ_UNRESOLVED",rel,rn,"readlink");return strdup("-");}if(fstat(fd,&after)<0||fstatat(parent,name,&pathst,AT_SYMLINK_NOFOLLOW)<0||!same_stat(&opened,&after)||!same_stat(&after,&pathst)){close(fd);issue(s,"SYMLINK_IDENTITY_RACE",rel,rn,"readlink");return strdup("-");}close(fd);return hex_bytes((unsigned char*)buf,(size_t)n);
}
static void walk(Snapshot *s,int fd,const unsigned char *absolute,size_t an,const unsigned char *rel,size_t rn,int depth,const struct stat *before,int parent,const char *name){
  if(s->stopped)return;
  check_deadline(s);if(s->entries>=ENTRY_CAP){issue(s,"ENTRY_CAP",rel,rn,"entries");s->stopped=1;return;}s->entries++;const char *type=kind(before->st_mode);int uploads=has_uploads_component(rel,rn);if(uploads)s->uploads++;if(S_ISDIR(before->st_mode))s->dirs_n++;else if(S_ISREG(before->st_mode))s->files++;else s->other++;
  char *target=strdup("-"),*filehash=strdup("-");if(!target||!filehash)die("allocation");
  if(S_ISLNK(before->st_mode)){free(target);target=symlink_target(s,parent,name,rel,rn,before);issue(s,"SYMLINK_UNRESOLVED",rel,rn,"no-follow");}
  else if(S_ISREG(before->st_mode)){if(before->st_nlink!=1)issue(s,"HARDLINK_UNRESOLVED",rel,rn,"nlink");if(s->files>FILE_CAP){issue(s,"FILE_CAP",rel,rn,"files");s->stopped=1;}if(!s->stopped){free(filehash);filehash=hash_regular(s,parent,name,rel,rn,before);}}
  else if(!S_ISDIR(before->st_mode))issue(s,"NONREGULAR_OBJECT_UNRESOLVED",rel,rn,type);
  char *rh=hex_bytes(rel,rn),*ah=hex_bytes(absolute,an);lines_add(&s->rows,fmt_alloc("ENTRY\t%s\t%s\t%s\t%lld\t%03o\t%u\t%u\t%lld\t%lld\t%llu\t%llu\t%llu\t%s\t%s\t%d",rh,ah,type,(long long)before->st_size,(unsigned)(before->st_mode&07777),(unsigned)before->st_uid,(unsigned)before->st_gid,ns_time(before->st_mtim),ns_time(before->st_ctim),(unsigned long long)before->st_dev,(unsigned long long)before->st_ino,(unsigned long long)before->st_nlink,target,filehash,uploads));free(rh);free(ah);free(target);free(filehash);
  if(!S_ISDIR(before->st_mode)||s->stopped)return;
  if(depth>DEPTH_CAP){issue(s,"DEPTH_CAP",rel,rn,"depth");return;}if(s->dirs_n>DIRECTORY_CAP){issue(s,"DIRECTORY_CAP",rel,rn,"dirs");s->stopped=1;return;}if(id_seen(s,before->st_dev,before->st_ino)){issue(s,"DIRECTORY_IDENTITY_REPEAT",rel,rn,"identity");return;}id_add(s,before->st_dev,before->st_ino);
  Bytes *first=NULL,*last=NULL;size_t fn=0,ln=0;if(read_names(s,fd,rel,rn,&first,&fn)<0)return;
  for(size_t i=0;i<fn&&!s->stopped;i++){size_t crn,can;char *cr=join_bytes(rel,rn,first[i].v,first[i].n,rn>0,&crn);char *ca=join_bytes(absolute,an,first[i].v,first[i].n,1,&can);if(crn>MAX_RELATIVE_BYTES){issue(s,"PATH_BYTE_CAP",(unsigned char*)cr,crn,"path");free(cr);free(ca);continue;}char nm[4097];if(first[i].n>=sizeof nm)die("name cap");memcpy(nm,first[i].v,first[i].n);nm[first[i].n]=0;struct stat child,final;if(fstatat(fd,nm,&child,AT_SYMLINK_NOFOLLOW)<0){issue(s,"ENTRY_STAT_UNRESOLVED",(unsigned char*)cr,crn,"stat");free(cr);free(ca);continue;}int cfd=-1;if(S_ISDIR(child.st_mode)){int used=0;cfd=open_component(fd,nm,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_NOATIME|O_CLOEXEC,&used);if(cfd<0){issue(s,"DIRECTORY_OPEN_UNRESOLVED",(unsigned char*)cr,crn,"open");free(cr);free(ca);continue;}struct stat op;if(fstat(cfd,&op)<0||!same_stat(&op,&child)){close(cfd);issue(s,"DIRECTORY_IDENTITY_RACE",(unsigned char*)cr,crn,"open");free(cr);free(ca);continue;}}
    walk(s,cfd,(unsigned char*)ca,can,(unsigned char*)cr,crn,depth+1,&child,fd,nm);if(cfd>=0)close(cfd);if(fstatat(fd,nm,&final,AT_SYMLINK_NOFOLLOW)<0)issue(s,"ENTRY_FINAL_RACE",(unsigned char*)cr,crn,"stat");else if(!same_stat(&child,&final))issue(s,"ENTRY_IDENTITY_RACE",(unsigned char*)cr,crn,"changed");free(cr);free(ca);
  }
  if(!s->stopped&&read_names(s,fd,rel,rn,&last,&ln)==0&&!names_equal(first,fn,last,ln))issue(s,"DIRECTORY_IDENTITY_RACE",rel,rn,"changed");
  names_free(first,fn);names_free(last,ln);
}
static char *snapshot(const char *root,const char *runtime_sha,const char *runtime_identity){
  Snapshot s={0};s.deadline=time(NULL)+MAX_SECONDS;s.requested_root=root;s.runtime_sha=runtime_sha;s.runtime_identity=runtime_identity;int used=0,fd=open_root(root,&used);struct stat rb,rp,ra;if(fstat(fd,&rb)<0||lstat(root,&rp)<0||!same_stat(&rb,&rp)||!S_ISDIR(rb.st_mode)){close(fd);die("physical root identity mismatch");}walk(&s,fd,(const unsigned char*)root,strlen(root),(const unsigned char*)"",0,0,&rb,-1,NULL);if(fstat(fd,&ra)<0||lstat(root,&rp)<0||!same_stat(&rb,&ra)||!same_stat(&ra,&rp))issue(&s,"ROOT_IDENTITY_RACE",(unsigned char*)"",0,"changed");close(fd);
  qsort(s.rows.v,s.rows.n,sizeof(char*),cmpstr);qsort(s.issues.v,s.issues.n,sizeof(char*),cmpstr);size_t unique=0;for(size_t i=0;i<s.issues.n;i++){if(i&&strcmp(s.issues.v[i],s.issues.v[i-1])==0){free(s.issues.v[i]);continue;}s.issues.v[unique++]=s.issues.v[i];}s.issues.n=unique;
  Sha256 inv;sha_init(&inv);for(size_t i=0;i<s.rows.n;i++){sha_update(&inv,s.rows.v[i],strlen(s.rows.v[i]));sha_update(&inv,"\n",1);}unsigned char db[32];char ih[65];sha_final(&inv,db);hex32(db,ih);
  char *roothex=hex_bytes((unsigned char*)root,strlen(root));char ri[65];digest(runtime_identity,strlen(runtime_identity),ri);char *runtimehex=hex_bytes((unsigned char*)RUNTIME_PATH,strlen(RUNTIME_PATH));
  Lines all={0};lines_add(&all,fmt_alloc("ROOT\t%s\t%s\t%llu\t%llu\t%03o\t%u\t%u\t%llu\t%lld\t%lld",roothex,roothex,(unsigned long long)rb.st_dev,(unsigned long long)rb.st_ino,(unsigned)(rb.st_mode&07777),(unsigned)rb.st_uid,(unsigned)rb.st_gid,(unsigned long long)rb.st_nlink,ns_time(rb.st_mtim),ns_time(rb.st_ctim)));lines_add(&all,fmt_alloc("RUNTIME\t%s\t%s\t%s\t%s",RUNTIME_MODE,runtimehex,runtime_sha,ri));
  for(size_t i=0;i<s.rows.n;i++){lines_add(&all,s.rows.v[i]);s.rows.v[i]=NULL;}for(size_t i=0;i<s.issues.n;i++){lines_add(&all,s.issues.v[i]);s.issues.v[i]=NULL;}
  lines_add(&all,fmt_alloc("SUMMARY\t%zu\t%zu\t%zu\t%zu\t%llu\t%zu\t%zu\t%zu\t%s\t%s\t200000\t50000\t150000\t1073741824\t34359738368\t64\t900\t4096\t125829120",s.entries,s.dirs_n,s.files,s.hashed,(unsigned long long)s.hashed_bytes,s.uploads,s.other,s.issues.n,(s.issues.n==0&&!s.stopped)?"true":"false",ih));qsort(all.v,all.n,sizeof(char*),cmpstr);
  size_t total=0;for(size_t i=0;i<all.n;i++)total+=strlen(all.v[i])+1;if(total>MAX_OUTPUT_BYTES)die("final serialized output byte cap exceeded");char *out=xmalloc(total+1),*q=out;for(size_t i=0;i<all.n;i++){size_t n=strlen(all.v[i]);memcpy(q,all.v[i],n);q+=n;*q++='\n';}*q=0;
  free(roothex);free(runtimehex);lines_free(&all);lines_free(&s.rows);lines_free(&s.issues);free(s.dirs.v);return out;
}
static size_t split_tabs(char *line,char **field,size_t cap){
  size_t n=0;char *p=line;
  if(!cap)return 0;
  field[n++]=p;
  while(*p){if(*p=='\t'){*p=0;if(n>=cap)return cap+1;field[n++]=p+1;}p++;}
  return n;
}
static int canonical_relhex(const char *text){
  size_t n=strlen(text);if(n&1)return 0;
  for(size_t i=0;i<n;i++)if(nibble(text[i])<0)return 0;
  if(!n)return 1;
  size_t raw_n=0;unsigned char *raw=decode_hex(text,&raw_n);if(!raw)return 0;
  size_t start=0;int ok=1;
  for(size_t i=0;i<=raw_n;i++)if(i==raw_n||raw[i]=='/'){
    if(!is_safe_component(raw+start,i-start)){ok=0;break;}start=i+1;
  }
  free(raw);return ok;
}
static int diagnostic_line_next(const char **cursor,const char **line,size_t *length){
  while(**cursor){
    const char *start=*cursor,*end=strchr(start,'\n');size_t n=end?(size_t)(end-start):strlen(start);*cursor=end?end+1:start+n;
    if(!n)continue;
    *line=start;*length=n;return 1;
  }
  return 0;
}
static int diagnostic_prefix(const char *line,size_t length,const char *prefix){size_t n=strlen(prefix);return length>=n&&!memcmp(line,prefix,n);}
static void diagnostic_record_copy(DiagnosticRecord *record,const char *line,size_t length){
  if(length>=sizeof record->storage)die("diagnostic line cap");
  memcpy(record->storage,line,length);record->storage[length]=0;memset(record->field,0,sizeof record->field);
}
static void parse_diagnostic_bindings(const char *snapshot_text,char root[11][8193],char runtime[5][1025]){
  const char *cursor=snapshot_text,*line;size_t length;int root_seen=0,runtime_seen=0;DiagnosticRecord record;
  while(diagnostic_line_next(&cursor,&line,&length)){
    if(diagnostic_prefix(line,length,"ROOT\t")){
      if(root_seen++)die("diagnostic duplicate root");
      diagnostic_record_copy(&record,line,length);if(split_tabs(record.storage,record.field,11)!=11)die("diagnostic root invalid");
      for(size_t i=0;i<11;i++){if(strlen(record.field[i])>=8193)die("diagnostic root field cap");strcpy(root[i],record.field[i]);}
    }else if(diagnostic_prefix(line,length,"RUNTIME\t")){
      if(runtime_seen++)die("diagnostic duplicate runtime");
      diagnostic_record_copy(&record,line,length);if(split_tabs(record.storage,record.field,5)!=5)die("diagnostic runtime invalid");
      for(size_t i=0;i<5;i++){if(strlen(record.field[i])>=1025)die("diagnostic runtime field cap");strcpy(runtime[i],record.field[i]);}
    }
  }
  if(root_seen!=1||runtime_seen!=1||strcmp(root[0],"ROOT")||strcmp(runtime[0],"RUNTIME"))die("diagnostic snapshot binding missing");
}
static int diagnostic_entry_next(DiagnosticCursor *cursor,DiagnosticRecord *record){
  const char *line;size_t length;
  while(diagnostic_line_next(&cursor->cursor,&line,&length))if(diagnostic_prefix(line,length,"ENTRY\t")){
    if(cursor->count>=ENTRY_CAP)die("diagnostic entry cap");
    diagnostic_record_copy(record,line,length);
    if(split_tabs(record->storage,record->field,16)!=16||strcmp(record->field[0],"ENTRY")||!canonical_relhex(record->field[1]))die("diagnostic source entry invalid");
    if(cursor->count&&strcmp(cursor->previous,record->field[1])>=0)die("diagnostic source ordering invalid");
    if(strlen(record->field[1])>=sizeof cursor->previous)die("diagnostic entry path cap");
    strcpy(cursor->previous,record->field[1]);cursor->count++;return 1;
  }
  return 0;
}
static int diagnostic_issue_next(DiagnosticCursor *cursor,DiagnosticRecord *record){
  const char *line;size_t length;
  while(diagnostic_line_next(&cursor->cursor,&line,&length))if(diagnostic_prefix(line,length,"UNRESOLVED\t")){
    if(cursor->count>=ENTRY_CAP)die("diagnostic issue cap");
    diagnostic_record_copy(record,line,length);
    if(cursor->count&&strcmp(cursor->previous,record->storage)>=0)die("diagnostic issue ordering invalid");
    if(strlen(record->storage)>=sizeof cursor->previous)die("diagnostic issue line cap");
    strcpy(cursor->previous,record->storage);
    if(split_tabs(record->storage,record->field,4)!=4||strcmp(record->field[0],"UNRESOLVED")||!canonical_relhex(record->field[2])||!valid_sha(record->field[3]))die("diagnostic source issue invalid");
    cursor->count++;return 1;
  }
  return 0;
}
static const char *diagnostic_change(const DiagnosticEntry *first,const DiagnosticEntry *second){
  if(!first)return "CREATED";
  if(!second)return "DELETED";
  if(strcmp(first->field[3],second->field[3])||strcmp(first->field[10],second->field[10])||strcmp(first->field[11],second->field[11]))return "REPLACED";
  return "MODIFIED";
}
static int diagnostic_entry_equal(const DiagnosticEntry *first,const DiagnosticEntry *second){for(size_t i=0;i<16;i++)if(strcmp(first->field[i],second->field[i]))return 0;return 1;}
static const char *diagnostic_value(const DiagnosticEntry *entry,size_t field){return entry?entry->field[field]:"-";}
static unsigned long long exact_unsigned(const char *text,const char *label){char tail;unsigned long long value;if(sscanf(text,"%llu%c",&value,&tail)!=1)die(label);return value;}
static long long exact_signed(const char *text,const char *label){char tail;long long value;if(sscanf(text,"%lld%c",&value,&tail)!=1)die(label);return value;}
static unsigned exact_octal(const char *text,const char *label){char tail;unsigned value;if(sscanf(text,"%o%c",&value,&tail)!=1||value>07777)die(label);return value;}
static void parse_volatile_policy(const char *token,VolatilePolicy *policy){
  size_t n=strlen(token);if(!n||n>32768)die("volatile policy token cap");char *copy=strdup(token);if(!copy)die("volatile policy allocation");char *save=NULL;
  for(char *item=strtok_r(copy,",",&save);item;item=strtok_r(NULL,",",&save)){
    if(policy->n>=64||strlen(item)<4||item[1]!=':'||(item[0]!='A'&&item[0]!='C'&&item[0]!='L')||!canonical_relhex(item+2))die("volatile policy token invalid");
    if(policy->n&&strcmp(policy->v[policy->n-1].path,item+2)>=0)die("volatile policy ordering invalid");
    policy->v[policy->n].behavior=item[0];policy->v[policy->n].path=strdup(item+2);if(!policy->v[policy->n].path)die("volatile policy allocation");policy->n++;
  }
  free(copy);if(!policy->n)die("volatile policy empty");
}
static void free_volatile_policy(VolatilePolicy *policy){for(size_t i=0;i<policy->n;i++)free(policy->v[i].path);memset(policy,0,sizeof *policy);}
static VolatileRule *volatile_rule(VolatilePolicy *policy,const char *path){for(size_t i=0;i<policy->n;i++)if(!strcmp(policy->v[i].path,path))return &policy->v[i];return NULL;}
static int ctime_only(const DiagnosticEntry *a,const DiagnosticEntry *b){for(size_t i=0;i<16;i++)if(i!=9&&strcmp(a->field[i],b->field[i]))return 0;return strcmp(a->field[9],b->field[9])!=0;}
static int monotonic_log_growth(const DiagnosticEntry *a,const DiagnosticEntry *b){
  static const size_t stable[]={3,5,6,7,10,11,12,13,15};for(size_t i=0;i<sizeof stable/sizeof stable[0];i++)if(strcmp(a->field[stable[i]],b->field[stable[i]]))return 0;
  size_t pathn=strlen(a->field[1]),raw_n=0;unsigned char *raw=decode_hex(a->field[1],&raw_n);int suffix=raw&&raw_n>=4&&!memcmp(raw+raw_n-4,".log",4);free(raw);
  if(!suffix||pathn>8192||strcmp(a->field[3],"REGULAR")||strcmp(a->field[15],"0")||strcmp(b->field[15],"0")||(exact_octal(a->field[5],"volatile mode invalid")&0111))return 0;
  return exact_unsigned(b->field[4],"volatile size invalid")>exact_unsigned(a->field[4],"volatile size invalid")&&exact_signed(b->field[8],"volatile mtime invalid")>=exact_signed(a->field[8],"volatile mtime invalid")&&exact_signed(b->field[9],"volatile ctime invalid")>=exact_signed(a->field[9],"volatile ctime invalid");
}
static void verify_log_prefix(const char *root,const DiagnosticEntry *a,const DiagnosticEntry *b,const char *uploads){
  if(strcmp(a->field[15],uploads)||strcmp(b->field[15],uploads))die("volatile log location marker invalid");
  size_t rn=0;unsigned char *rel=decode_hex(a->field[1],&rn);if(!rel)die("volatile log path invalid");
  int used=0,rootfd=open_root(root,&used),parent=rootfd;struct stat root_before,root_after;if(fstat(rootfd,&root_before)<0)die("volatile upload root identity unavailable");size_t start=0;char name[4097]={0};
  for(size_t i=0;i<=rn;i++)if(i==rn||rel[i]=='/'){size_t n=i-start;if(!is_safe_component(rel+start,n)||n>=sizeof name)die("volatile upload path component invalid");memcpy(name,rel+start,n);name[n]=0;if(i<rn){int next=open_component(parent,name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_NOATIME|O_CLOEXEC,&used);if(next<0)die("volatile upload parent traversal failed");if(parent!=rootfd)close(parent);parent=next;}start=i+1;}
  int fd=open_component(parent,name,O_RDONLY|O_NOFOLLOW|O_NOATIME|O_CLOEXEC,&used);struct stat opened,after,pathst;if(fd<0||fstat(fd,&opened)<0||!S_ISREG(opened.st_mode)||opened.st_dev!=(dev_t)exact_unsigned(b->field[10],"volatile upload device invalid")||opened.st_ino!=(ino_t)exact_unsigned(b->field[11],"volatile upload inode invalid")||(unsigned)(opened.st_mode&07777)!=exact_octal(b->field[5],"volatile upload mode invalid")||(opened.st_mode&0111)||opened.st_uid!=(uid_t)exact_unsigned(b->field[6],"volatile upload uid invalid")||opened.st_gid!=(gid_t)exact_unsigned(b->field[7],"volatile upload gid invalid")||opened.st_nlink!=(nlink_t)exact_unsigned(b->field[12],"volatile upload nlink invalid")||(unsigned long long)opened.st_size!=exact_unsigned(b->field[4],"volatile upload size invalid")||ns_time(opened.st_mtim)!=exact_signed(b->field[8],"volatile upload mtime invalid")||ns_time(opened.st_ctim)!=exact_signed(b->field[9],"volatile upload ctime invalid"))die("volatile upload current identity mismatch");
  unsigned long long prefix=exact_unsigned(a->field[4],"volatile upload prefix size invalid");Sha256 sh;sha_init(&sh);unsigned char *buf=xmalloc(IO_CHUNK);unsigned long long total=0;while(total<prefix){size_t want=(size_t)((prefix-total)>IO_CHUNK?IO_CHUNK:(prefix-total));ssize_t got=read(fd,buf,want);if(got<=0)die("volatile upload prefix read failed");sha_update(&sh,buf,(size_t)got);total+=(unsigned long long)got;}free(buf);unsigned char hash[32];char actual[65];sha_final(&sh,hash);hex32(hash,actual);
  if(strcmp(actual,a->field[14])||fstat(fd,&after)<0||fstatat(parent,name,&pathst,AT_SYMLINK_NOFOLLOW)<0||fstat(rootfd,&root_after)<0||!same_stat(&opened,&after)||!same_stat(&after,&pathst)||!same_stat(&root_before,&root_after))die("volatile upload append-prefix proof failed");
  close(fd);if(parent!=rootfd)close(parent);close(rootfd);free(rel);
}
static void emit_volatile_inventory(const char *root,const char *first_text,const char *second_text,const char *nonce,const char *policy_token){
  char root1[11][8193]={{0}},root2[11][8193]={{0}},runtime1[5][1025]={{0}},runtime2[5][1025]={{0}};VolatilePolicy policy={0};
  parse_diagnostic_bindings(first_text,root1,runtime1);parse_diagnostic_bindings(second_text,root2,runtime2);parse_volatile_policy(policy_token,&policy);
  if(strcmp(root1[1],root2[1])||strcmp(root1[3],root2[3])||strcmp(root1[4],root2[4])||strcmp(runtime1[1],runtime2[1])||strcmp(runtime1[2],runtime2[2])||strcmp(runtime1[3],runtime2[3])||strcmp(runtime1[4],runtime2[4]))die("volatile inventory identity mismatch");
  DiagnosticCursor first_issues={.cursor=first_text},second_issues={.cursor=second_text};DiagnosticRecord first_issue,second_issue;size_t first_issue_count=0,second_issue_count=0;
  while(diagnostic_issue_next(&first_issues,&first_issue))first_issue_count++;
  while(diagnostic_issue_next(&second_issues,&second_issue))second_issue_count++;
  if(first_issue_count||second_issue_count)die("volatile inventory unresolved evidence");
  DiagnosticCursor first_entries={.cursor=first_text},second_entries={.cursor=second_text};DiagnosticRecord first_record,second_record;int have_first=diagnostic_entry_next(&first_entries,&first_record),have_second=diagnostic_entry_next(&second_entries,&second_record);
  while(have_first||have_second){DiagnosticEntry a={.storage=first_record.storage},b={.storage=second_record.storage};if(have_first)memcpy(a.field,first_record.field,sizeof a.field);if(have_second)memcpy(b.field,second_record.field,sizeof b.field);int order=have_first&&have_second?strcmp(a.field[1],b.field[1]):(have_first?-1:1);
    if(order!=0)die("volatile inventory create/delete event");
    VolatileRule *rule=volatile_rule(&policy,a.field[1]);if(rule)rule->present=1;if(!diagnostic_entry_equal(&a,&b)){if(!rule)die("volatile inventory unclassified drift");if(rule->behavior=='C'&&(!ctime_only(&a,&b)||(exact_octal(a.field[5],"volatile mode invalid")&0111)||(exact_octal(b.field[5],"volatile mode invalid")&0111)))die("volatile inventory behavior mismatch");if(rule->behavior=='L'){if(!monotonic_log_growth(&a,&b))die("volatile log behavior mismatch");verify_log_prefix(root,&a,&b,"0");}if(rule->behavior=='A'){if(!monotonic_log_growth(&a,&b))die("volatile upload behavior mismatch");verify_log_prefix(root,&a,&b,"1");}rule->observed=1;}else if(rule){if(strcmp(a.field[3],"REGULAR")||(exact_octal(a.field[5],"volatile mode invalid")&0111)||(rule->behavior=='A'?strcmp(a.field[15],"1"):strcmp(a.field[15],"0")))die("volatile stable target invalid");rule->observed=0;}have_first=diagnostic_entry_next(&first_entries,&first_record);have_second=diagnostic_entry_next(&second_entries,&second_record);
  }
  for(size_t k=0;k<policy.n;k++)if(!policy.v[k].present)die("volatile policy target missing");
  char token_sha[65];digest(policy_token,strlen(policy_token),token_sha);Lines trailer={0};lines_add(&trailer,fmt_alloc("VOLATILE_RUNTIME_CANDIDATE\tBOUNDED_VOLATILE_RUNTIME_CANDIDATE_V1\t%s\t%zu\tVISIBLE\tUNVERIFIED_NON_AUTHORIZING",token_sha,policy.n));
  for(size_t k=0;k<policy.n;k++)lines_add(&trailer,fmt_alloc("VOLATILE_RUNTIME_CANDIDATE_PATH\t%s\t%s\t%s",policy.v[k].path,policy.v[k].behavior=='C'?"CTIME_ONLY":policy.v[k].behavior=='A'?"APPEND_PREFIX_VERIFIED_UPLOAD_LOG_GROWTH":"APPEND_PREFIX_VERIFIED_LOG_GROWTH",policy.v[k].observed?"OBSERVED_DRIFT":"OBSERVED_STABLE"));
  size_t total=strlen("CAPTURE_NONCE\t")+strlen(nonce)+1+strlen(second_text);for(size_t k=0;k<trailer.n;k++)total+=strlen(trailer.v[k])+1;if(total>MAX_OUTPUT_BYTES)die("volatile inventory serialized output cap");
  if(printf("CAPTURE_NONCE\t%s\n",nonce)<0||fputs(second_text,stdout)==EOF)die("output write failure");
  for(size_t k=0;k<trailer.n;k++)if(fputs(trailer.v[k],stdout)==EOF||fputc('\n',stdout)==EOF)die("output write failure");if(fflush(stdout)==EOF)die("output write failure");
  lines_free(&trailer);free_volatile_policy(&policy);
}
static char *diagnostic_delta(const char *first_text,const char *second_text,const char *nonce,const char *helper_sha,const char *runtime_identity){
  if(!strcmp(first_text,second_text))die("diagnostic mode requires two-pass mismatch");
  char root1[11][8193]={{0}},root2[11][8193]={{0}},runtime1[5][1025]={{0}},runtime2[5][1025]={{0}};
  parse_diagnostic_bindings(first_text,root1,runtime1);parse_diagnostic_bindings(second_text,root2,runtime2);
  if(strcmp(root1[1],root2[1])||strcmp(runtime1[1],runtime2[1])||strcmp(runtime1[2],runtime2[2])||strcmp(runtime1[3],helper_sha)||strcmp(runtime2[3],helper_sha)||strcmp(runtime1[4],runtime2[4]))die("diagnostic snapshot identity mismatch");
  char first_sha[65],second_sha[65];digest(first_text,strlen(first_text),first_sha);digest(second_text,strlen(second_text),second_sha);
  Lines deltas={0};DiagnosticCursor first_entries={.cursor=first_text},second_entries={.cursor=second_text};DiagnosticRecord first_entry,second_entry;int have_first=diagnostic_entry_next(&first_entries,&first_entry),have_second=diagnostic_entry_next(&second_entries,&second_entry);
  while(have_first||have_second){
    DiagnosticEntry a={0},b={0};if(have_first){a.storage=first_entry.storage;memcpy(a.field,first_entry.field,sizeof a.field);}if(have_second){b.storage=second_entry.storage;memcpy(b.field,second_entry.field,sizeof b.field);}int order=have_first&&have_second?strcmp(a.field[1],b.field[1]):(have_first?-1:1);
    if(order==0&&diagnostic_entry_equal(&a,&b)){have_first=diagnostic_entry_next(&first_entries,&first_entry);have_second=diagnostic_entry_next(&second_entries,&second_entry);continue;}
    DiagnosticEntry *left=order<=0?&a:NULL,*right=order>=0?&b:NULL;const char *path=left?left->field[1]:right->field[1];
    lines_add(&deltas,fmt_alloc("DRIFT\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s",path,diagnostic_change(left,right),left?"true":"false",right?"true":"false",diagnostic_value(left,3),diagnostic_value(left,10),diagnostic_value(left,11),diagnostic_value(left,4),diagnostic_value(left,5),diagnostic_value(left,6),diagnostic_value(left,7),diagnostic_value(left,12),diagnostic_value(left,8),diagnostic_value(left,9),diagnostic_value(left,14),diagnostic_value(left,13),diagnostic_value(left,15),diagnostic_value(right,3),diagnostic_value(right,10),diagnostic_value(right,11),diagnostic_value(right,4),diagnostic_value(right,5),diagnostic_value(right,6),diagnostic_value(right,7),diagnostic_value(right,12),diagnostic_value(right,8),diagnostic_value(right,9),diagnostic_value(right,14),diagnostic_value(right,13),diagnostic_value(right,15)));
    if(order<=0)have_first=diagnostic_entry_next(&first_entries,&first_entry);
    if(order>=0)have_second=diagnostic_entry_next(&second_entries,&second_entry);
  }
  Lines issue_deltas={0};DiagnosticCursor first_issues={.cursor=first_text},second_issues={.cursor=second_text};DiagnosticRecord first_issue,second_issue;have_first=diagnostic_issue_next(&first_issues,&first_issue);have_second=diagnostic_issue_next(&second_issues,&second_issue);
  while(have_first||have_second){
    int order=have_first&&have_second?strcmp(first_issues.previous,second_issues.previous):(have_first?-1:1);if(order==0){have_first=diagnostic_issue_next(&first_issues,&first_issue);have_second=diagnostic_issue_next(&second_issues,&second_issue);continue;}
    DiagnosticRecord *issue=order<0?&first_issue:&second_issue;lines_add(&issue_deltas,fmt_alloc("DRIFT_ISSUE\t%s\t%s\t%s\t%s\t%s",issue->field[2],issue->field[1],issue->field[3],order<0?"true":"false",order>0?"true":"false"));if(order<0)have_first=diagnostic_issue_next(&first_issues,&first_issue);else have_second=diagnostic_issue_next(&second_issues,&second_issue);
  }
  if(deltas.n>ENTRY_CAP||issue_deltas.n>ENTRY_CAP||deltas.n+issue_deltas.n==0)die("diagnostic mismatch not fully explainable");
  char *runtime_identity_sha=runtime1[4],*runtime_identity_hex=hex_bytes((unsigned char*)runtime_identity,strlen(runtime_identity));Lines output={0};
  lines_add(&output,fmt_alloc("CAPTURE_NONCE\t%s",nonce));
  lines_add(&output,fmt_alloc("DRIFT_DIAGNOSTIC\tSIGNED_DRIFT_DIAGNOSTIC_MODE_V1\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%zu\t%zu\t%s\t%s",root1[1],root1[3],root1[4],root2[3],root2[4],first_sha,second_sha,helper_sha,runtime_identity_sha,runtime_identity_hex,deltas.n,issue_deltas.n,"READ_ONLY","NON_AUTHORIZING"));
  for(size_t k=0;k<deltas.n;k++){lines_add(&output,deltas.v[k]);deltas.v[k]=NULL;}
  for(size_t k=0;k<issue_deltas.n;k++){lines_add(&output,issue_deltas.v[k]);issue_deltas.v[k]=NULL;}
  size_t total=1;for(size_t k=0;k<output.n;k++)total+=strlen(output.v[k])+1;if(total>MAX_OUTPUT_BYTES)die("diagnostic serialized output cap");char *serialized=xmalloc(total),*cursor=serialized;
  for(size_t k=0;k<output.n;k++){size_t n=strlen(output.v[k]);memcpy(cursor,output.v[k],n);cursor+=n;*cursor++='\n';}*cursor=0;
  free(runtime_identity_hex);lines_free(&deltas);lines_free(&issue_deltas);lines_free(&output);return serialized;
}
static int valid_sha(const char *s){if(strlen(s)!=64)return 0;for(int i=0;i<64;i++)if(!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f')))return 0;return 1;}
static void emit_capture(const char *nonce,const char *payload){if(printf("CAPTURE_NONCE\t%s\n",nonce)<0||fputs(payload,stdout)==EOF||fflush(stdout)==EOF)die("output write failure");}
static void emit_payload(const char *payload){if(fputs(payload,stdout)==EOF||fflush(stdout)==EOF)die("output write failure");}
static int valid_root(const char *s){
  size_t n,components=0,start=1;
  if(!s||s[0]!='/'||(n=strlen(s))<2||n>MAX_RELATIVE_BYTES||s[n-1]=='/')return 0;
  for(size_t i=1;i<=n;i++)if(i==n||s[i]=='/'){
    size_t length=i-start;
    if(!is_safe_component((const unsigned char*)s+start,length)||++components>DEPTH_CAP)return 0;
    start=i+1;
  }
  return components>0;
}
static int valid_nonce(const char *s){return valid_sha(s);}
static void verify_self_fd(const char *text,const char *expected){char tail;long value;if(sscanf(text,"%ld%c",&value,&tail)!=1||value<3||value>1048576)die("invalid helper descriptor");int fd=(int)value;struct stat st;if(fstat(fd,&st)<0||!S_ISREG(st.st_mode)||st.st_size<=0||st.st_size>1048576)die("helper descriptor identity");int seals=fcntl(fd,F_GET_SEALS);if(seals<0||(seals&(F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE))!=(F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE))die("helper descriptor not sealed");Sha256 sh;sha_init(&sh);unsigned char buf[65536];off_t off=0;for(;;){ssize_t n=pread(fd,buf,sizeof buf,off);if(n<0)die("helper descriptor read");if(!n)break;sha_update(&sh,buf,(size_t)n);off+=n;if(off>1048576)die("helper descriptor cap");}if(off!=st.st_size)die("helper descriptor size drift");unsigned char raw[32];char actual[65];sha_final(&sh,raw);hex32(raw,actual);if(strcmp(actual,expected))die("helper SHA-256 mismatch");if(fcntl(fd,F_SETFD,FD_CLOEXEC)<0)die("helper descriptor close-on-exec");}
static int nibble(char c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;return -1;}
static unsigned char *decode_hex(const char *text,size_t *outn){size_t n=strlen(text);if(!n||(n&1)||n/2>MAX_RELATIVE_BYTES)return NULL;unsigned char *out=xmalloc(n/2+1);for(size_t i=0;i<n;i+=2){int a=nibble(text[i]),b=nibble(text[i+1]);if(a<0||b<0){free(out);return NULL;}out[i/2]=(unsigned char)((a<<4)|b);}out[n/2]=0;*outn=n/2;return out;}
static char *selected_snapshot(const char *root,const char *relhex,const char *runtime_sha,const char *runtime_identity){
  size_t rn=0;unsigned char *rel=decode_hex(relhex,&rn);if(!rel)die("invalid selected relative path");int used=0,rootfd=open_root(root,&used),parent=rootfd;size_t start=0;char final_name[4097]={0};
  struct stat ancestors[DEPTH_CAP+1],root_path_before,root_path_after;size_t ancestor_count=1;Lines path_bindings={0};
  if(fstat(rootfd,&ancestors[0])<0||lstat(root,&root_path_before)<0||!same_stat(&ancestors[0],&root_path_before))die("selected canonical root identity mismatch");
  char *roothex=hex_bytes((const unsigned char*)root,strlen(root));
  lines_add(&path_bindings,fmt_alloc("ROLLBACK_PATH\tROOT\t%s\t%03o\t%u\t%u\t%lld\t%lld\t%llu\t%llu\t%llu",roothex,(unsigned)(ancestors[0].st_mode&07777),(unsigned)ancestors[0].st_uid,(unsigned)ancestors[0].st_gid,ns_time(ancestors[0].st_mtim),ns_time(ancestors[0].st_ctim),(unsigned long long)ancestors[0].st_dev,(unsigned long long)ancestors[0].st_ino,(unsigned long long)ancestors[0].st_nlink));free(roothex);
  for(size_t i=0;i<=rn;i++)if(i==rn||rel[i]=='/'){
    size_t n=i-start;if(!is_safe_component(rel+start,n)||n>=sizeof final_name){if(parent!=rootfd)close(parent);close(rootfd);free(rel);die("unsafe selected path component");}
    memcpy(final_name,rel+start,n);final_name[n]=0;
    if(i<rn){
      int next=open_component(parent,final_name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_NOATIME|O_CLOEXEC,&used);
      if(next<0||ancestor_count>DEPTH_CAP){if(next>=0)close(next);if(parent!=rootfd)close(parent);close(rootfd);free(rel);die("selected parent traversal failed");}
      if(fstat(next,&ancestors[ancestor_count])<0){close(next);if(parent!=rootfd)close(parent);close(rootfd);free(rel);die("selected parent identity unavailable");}
      char *ancestor_hex=hex_bytes(rel,i);
      lines_add(&path_bindings,fmt_alloc("ROLLBACK_PATH\tANCESTOR\t%s\t%03o\t%u\t%u\t%lld\t%lld\t%llu\t%llu\t%llu",ancestor_hex,(unsigned)(ancestors[ancestor_count].st_mode&07777),(unsigned)ancestors[ancestor_count].st_uid,(unsigned)ancestors[ancestor_count].st_gid,ns_time(ancestors[ancestor_count].st_mtim),ns_time(ancestors[ancestor_count].st_ctim),(unsigned long long)ancestors[ancestor_count].st_dev,(unsigned long long)ancestors[ancestor_count].st_ino,(unsigned long long)ancestors[ancestor_count].st_nlink));free(ancestor_hex);
      ancestor_count++;if(parent!=rootfd)close(parent);parent=next;
    }
    start=i+1;
  }
  struct stat before,opened,after,pathst,root_before,root_after;if(fstat(rootfd,&root_before)<0||fstatat(parent,final_name,&before,AT_SYMLINK_NOFOLLOW)<0||!S_ISREG(before.st_mode)||before.st_nlink!=1||(uint64_t)before.st_size>MAX_ROLLBACK_BYTES){if(parent!=rootfd)close(parent);close(rootfd);free(rel);die("selected target prestate invalid");}
  int fd=open_component(parent,final_name,O_RDONLY|O_NOFOLLOW|O_NOATIME|O_CLOEXEC,&used);if(fd<0||fstat(fd,&opened)<0||!same_stat(&before,&opened)){if(fd>=0)close(fd);if(parent!=rootfd)close(parent);close(rootfd);free(rel);die("selected target atime-safe open failed");}
  size_t size=(size_t)before.st_size;unsigned char *bytes=xmalloc(size?size:1);size_t off=0;while(off<size){ssize_t n=read(fd,bytes+off,size-off);if(n<=0){close(fd);if(parent!=rootfd)close(parent);close(rootfd);free(rel);free(bytes);die("selected target read failed");}off+=(size_t)n;}
  unsigned char extra;
  if(read(fd,&extra,1)!=0||fstat(fd,&after)<0||fstatat(parent,final_name,&pathst,AT_SYMLINK_NOFOLLOW)<0||fstat(rootfd,&root_after)<0||lstat(root,&root_path_after)<0||!same_stat(&opened,&after)||!same_stat(&after,&pathst)||!same_stat(&root_before,&root_after)||!same_stat(&root_after,&root_path_after)){close(fd);if(parent!=rootfd)close(parent);close(rootfd);free(rel);free(bytes);die("selected target drift");}
  /* Reopen the canonical pathname and rewalk every parent after reading.  This
     proves the bytes still belong to the current root mapping, not a detached
     descriptor tree that was atomically substituted during capture. */
  int verify_used=0,verify_root=open_root(root,&verify_used),verify_parent=verify_root;struct stat verify_stat;size_t verify_index=1;start=0;
  if(fstat(verify_root,&verify_stat)<0||!same_stat(&verify_stat,&ancestors[0])){close(verify_root);close(fd);if(parent!=rootfd)close(parent);close(rootfd);free(rel);free(bytes);die("selected canonical root substituted");}
  for(size_t i=0;i<=rn;i++)if(i==rn||rel[i]=='/'){
    size_t n=i-start;memcpy(final_name,rel+start,n);final_name[n]=0;
    if(i<rn){
      int next=open_component(verify_parent,final_name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_NOATIME|O_CLOEXEC,&verify_used);
      if(next<0||verify_index>=ancestor_count||fstat(next,&verify_stat)<0||!same_stat(&verify_stat,&ancestors[verify_index])){if(next>=0)close(next);if(verify_parent!=verify_root)close(verify_parent);close(verify_root);close(fd);if(parent!=rootfd)close(parent);close(rootfd);free(rel);free(bytes);die("selected canonical ancestor substituted");}
      verify_index++;if(verify_parent!=verify_root)close(verify_parent);verify_parent=next;
    }
    start=i+1;
  }
  if(verify_index!=ancestor_count||fstatat(verify_parent,final_name,&verify_stat,AT_SYMLINK_NOFOLLOW)<0||!same_stat(&verify_stat,&after)){if(verify_parent!=verify_root)close(verify_parent);close(verify_root);close(fd);if(parent!=rootfd)close(parent);close(rootfd);free(rel);free(bytes);die("selected canonical target substituted");}
  if(verify_parent!=verify_root)close(verify_parent);
  close(verify_root);close(fd);if(parent!=rootfd)close(parent);close(rootfd);
  char file_sha[65],identity_sha[65];digest(bytes,size,file_sha);digest(runtime_identity,strlen(runtime_identity),identity_sha);char *bytehex=hex_bytes(bytes,size),*absolute=fmt_alloc("%s/%s",root,rel),*abshex=hex_bytes((unsigned char*)absolute,strlen(absolute)),*runtimehex=hex_bytes((unsigned char*)RUNTIME_PATH,strlen(RUNTIME_PATH));
  Lines all={0};lines_add(&all,fmt_alloc("ROLLBACK_RUNTIME\t%s\t%s\t%s\t%s",RUNTIME_MODE,runtimehex,runtime_sha,identity_sha));for(size_t i=0;i<path_bindings.n;i++)lines_add(&all,strdup(path_bindings.v[i]));lines_add(&all,fmt_alloc("SELECTED_ROLLBACK\t%s\t%s\t%zu\t%03o\t%u\t%u\t%lld\t%lld\t%llu\t%llu\t%llu\t%s\t%s",relhex,abshex,size,(unsigned)(before.st_mode&07777),(unsigned)before.st_uid,(unsigned)before.st_gid,ns_time(before.st_mtim),ns_time(before.st_ctim),(unsigned long long)before.st_dev,(unsigned long long)before.st_ino,(unsigned long long)before.st_nlink,file_sha,bytehex));
  size_t outn=1;for(size_t i=0;i<all.n;i++)outn+=strlen(all.v[i])+1;char *out=xmalloc(outn),*cursor=out;for(size_t i=0;i<all.n;i++){size_t n=strlen(all.v[i]);memcpy(cursor,all.v[i],n);cursor+=n;*cursor++='\n';}*cursor=0;
  free(rel);free(bytes);free(bytehex);free(absolute);free(abshex);free(runtimehex);lines_free(&path_bindings);lines_free(&all);return out;
}
int main(int argc,char **argv){
  if(argc==2&&!strcmp(argv[1],"--platform-probe")){puts("SUPPORTED:linux-x86_64");return 0;}
  apply_process_limits();if((argc!=7&&argc!=8)||!valid_root(argv[2])||!valid_nonce(argv[3])||!valid_sha(argv[4])||strlen(argv[5])>512)die("invalid bounded invocation");verify_self_fd(argv[6],argv[4]);
  if(argc==7&&!strcmp(argv[1],"inventory")){char *first=snapshot(argv[2],argv[4],argv[5]);char *second=snapshot(argv[2],argv[4],argv[5]);if(strcmp(first,second))die("inventory drift between passes");emit_capture(argv[3],first);free(first);free(second);return 0;}
  if(argc==7&&!strcmp(argv[1],"diagnostic")){char *first=snapshot(argv[2],argv[4],argv[5]);char *second=snapshot(argv[2],argv[4],argv[5]);char *delta=diagnostic_delta(first,second,argv[3],argv[4],argv[5]);emit_payload(delta);free(delta);free(first);free(second);return 0;}
  if(argc==8&&!strcmp(argv[1],"volatile-inventory")){char *first=snapshot(argv[2],argv[4],argv[5]);char *second=snapshot(argv[2],argv[4],argv[5]);emit_volatile_inventory(argv[2],first,second,argv[3],argv[7]);free(first);free(second);return 0;}
  if(argc==8&&!strcmp(argv[1],"rollback")){char *first=selected_snapshot(argv[2],argv[7],argv[4],argv[5]);char *second=selected_snapshot(argv[2],argv[7],argv[4],argv[5]);if(strcmp(first,second))die("selected target drift between passes");emit_capture(argv[3],first);free(first);free(second);return 0;}
  die("unsupported bounded mode");return 20;
}
#endif
