#define _GNU_SOURCE
#include <stdio.h>

#if !defined(__linux__) || !defined(__x86_64__)
int main(void) {
    fputs("wapp-native-exact-file-quarantine: unsupported platform\n", stderr);
    return 78;
}
#else

#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#if defined(__clang__)
#pragma clang diagnostic ignored "-Wlogical-op-parentheses"
#endif

#define TARGET_CAP 64
#define MANIFEST_CAP 65536
#define PATH_CAP 4096
#define IO_CHUNK (1024U * 1024U)
#define RENAME_NOREPLACE 1U

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
static uint32_t rotr(uint32_t x,unsigned n){return (x>>n)|(x<<(32-n));}
static void sha_block(Sha256 *s,const unsigned char *p){uint32_t w[64],a,b,c,d,e,f,g,h,t1,t2;unsigned i;for(i=0;i<16;i++)w[i]=((uint32_t)p[i*4]<<24)|((uint32_t)p[i*4+1]<<16)|((uint32_t)p[i*4+2]<<8)|p[i*4+3];for(i=16;i<64;i++){uint32_t x=w[i-15],y=w[i-2];w[i]=(rotr(y,17)^rotr(y,19)^(y>>10))+w[i-7]+(rotr(x,7)^rotr(x,18)^(x>>3))+w[i-16];}a=s->h[0];b=s->h[1];c=s->h[2];d=s->h[3];e=s->h[4];f=s->h[5];g=s->h[6];h=s->h[7];for(i=0;i<64;i++){t1=h+(rotr(e,6)^rotr(e,11)^rotr(e,25))+((e&f)^((~e)&g))+K[i]+w[i];t2=(rotr(a,2)^rotr(a,13)^rotr(a,22))+((a&b)^(a&c)^(b&c));h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;}s->h[0]+=a;s->h[1]+=b;s->h[2]+=c;s->h[3]+=d;s->h[4]+=e;s->h[5]+=f;s->h[6]+=g;s->h[7]+=h;}
static void sha_init(Sha256 *s){static const uint32_t H[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};memcpy(s->h,H,sizeof H);s->bits=0;s->used=0;}
static void sha_update(Sha256 *s,const void *v,size_t n){const unsigned char *p=v;s->bits+=(uint64_t)n*8;while(n){size_t take=64-s->used;if(take>n)take=n;memcpy(s->block+s->used,p,take);s->used+=take;p+=take;n-=take;if(s->used==64){sha_block(s,s->block);s->used=0;}}}
static void sha_finish(Sha256 *s,unsigned char out[32]){unsigned i;s->block[s->used++]=0x80;if(s->used>56){while(s->used<64)s->block[s->used++]=0;sha_block(s,s->block);s->used=0;}while(s->used<56)s->block[s->used++]=0;for(i=0;i<8;i++)s->block[63-i]=(unsigned char)(s->bits>>(8*i));sha_block(s,s->block);for(i=0;i<8;i++){out[i*4]=(unsigned char)(s->h[i]>>24);out[i*4+1]=(unsigned char)(s->h[i]>>16);out[i*4+2]=(unsigned char)(s->h[i]>>8);out[i*4+3]=(unsigned char)s->h[i];}}
static void hex32(const unsigned char in[32],char out[65]){static const char H[]="0123456789abcdef";for(int i=0;i<32;i++){out[i*2]=H[in[i]>>4];out[i*2+1]=H[in[i]&15];}out[64]=0;}

typedef struct {
    char path[PATH_CAP + 1];
    char sha[65];
    uint64_t size, parent_dev, parent_ino, dev, ino;
    uint32_t mode, uid, gid;
    int live_parent, quarantine_parent, object_fd;
    char live_name[256], quarantine_name[256];
    int moved;
} Target;

static Target targets[TARGET_CAP];
static size_t target_count;
static int root_fd=-1,parent_fd=-1,qroot_fd=-1,files_fd=-1,journal_fd=-1;
static uint64_t root_device;
static char qname[96];
static int mutation_started;

#if defined(WAPP_TEST_FAULT_INJECTION)
static void test_crash(const char *point){const char *value=getenv("WAPP_TEST_CRASH_POINT");if(value&&strcmp(value,point)==0)_exit(99);}
#else
static void test_crash(const char *point){(void)point;}
#endif

static void die(const char *m){if(mutation_started){fprintf(stdout,"WAPP_EXACT_FILE_STATE_V1\tPARTIAL_OR_DIVERGED\t%s\n",m);fflush(stdout);exit(22);}fprintf(stderr,"wapp-native-exact-file-quarantine: %s\n",m);exit(20);}
static void partial(const char *m){fprintf(stdout,"WAPP_EXACT_FILE_STATE_V1\tPARTIAL_OR_DIVERGED\t%s\n",m);fflush(stdout);exit(22);}
static int valid_hex(const char *s,size_t n){if(strlen(s)!=n)return 0;for(size_t i=0;i<n;i++)if(!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f')))return 0;return 1;}
static int nibble(char c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;return -1;}
static int valid_root(const char *p){size_t n;if(!p||p[0]!='/'||(n=strlen(p))<2||n>PATH_CAP||p[n-1]=='/'||strstr(p,"//"))return 0;for(const char *s=p+1;*s;){const char *e=strchr(s,'/');size_t z=e?(size_t)(e-s):strlen(s);if(!z||(z==1&&s[0]=='.')||(z==2&&s[0]=='.'&&s[1]=='.'))return 0;if(!e)break;s=e+1;}return 1;}
static uint64_t number(const char *s,const char *label){char *end=NULL;errno=0;unsigned long long v=strtoull(s,&end,10);if(errno||!s[0]||!end||*end){(void)label;die("invalid numeric manifest field");}return (uint64_t)v;}
static int open_beneath(int d,const char *p,int flags){struct open_how how={.flags=(uint64_t)flags,.resolve=RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS};return (int)syscall(SYS_openat2,d,p,&how,sizeof how);}
static int open_abs(const char *path,int flags){int d=open("/",O_PATH|O_DIRECTORY|O_CLOEXEC);if(d<0)die("root descriptor unavailable");int r=open_beneath(d,path+1,flags|O_CLOEXEC);close(d);if(r<0)die("absolute descriptor path unavailable");return r;}
static void write_all(int fd,const void *v,size_t n){const unsigned char *p=v;size_t o=0;while(o<n){ssize_t z=write(fd,p+o,n-o);if(z<0&&errno==EINTR)continue;if(z<=0)die("durable write failed");o+=(size_t)z;}}
static void sha_bytes(const void *v,size_t n,char out[65]){Sha256 s;unsigned char d[32];sha_init(&s);sha_update(&s,v,n);sha_finish(&s,d);hex32(d,out);}
static void sha_fd(int fd,char out[65]){Sha256 s;unsigned char d[32],buf[IO_CHUNK];sha_init(&s);if(lseek(fd,0,SEEK_SET)<0)die("file seek failed");for(;;){ssize_t n=read(fd,buf,sizeof buf);if(n<0&&errno==EINTR)continue;if(n<0)die("file read failed");if(!n)break;sha_update(&s,buf,(size_t)n);}sha_finish(&s,d);hex32(d,out);}
static int absent_at(int d,const char *n){struct stat st;if(fstatat(d,n,&st,AT_SYMLINK_NOFOLLOW)==0)return 0;if(errno==ENOENT)return 1;die("path absence observation failed");return 0;}
static int exact_stat(const struct stat *st,const Target *t,int quarantined){return S_ISREG(st->st_mode)&&(uint64_t)st->st_dev==t->dev&&(uint64_t)st->st_ino==t->ino&&(uint64_t)st->st_size==t->size&&st->st_nlink==1&&(uint32_t)st->st_uid==t->uid&&(uint32_t)st->st_gid==t->gid&&(uint32_t)(st->st_mode&07777)==(quarantined?0400U:t->mode);}
static int open_exact_at(int d,const char *name,Target *t,int quarantined){int fd=open_beneath(d,name,O_RDONLY|O_NOFOLLOW);if(fd<0)return -1;struct stat st;char hash[65];if(fstat(fd,&st)<0){close(fd);return -1;}sha_fd(fd,hash);if(!exact_stat(&st,t,quarantined)||strcmp(hash,t->sha)){close(fd);errno=ESTALE;return -1;}return fd;}
static int open_exact_quarantine_recovery(int d,const char *name,Target *t){int fd=open_beneath(d,name,O_RDONLY|O_NOFOLLOW);if(fd<0)return -1;struct stat st;char hash[65];if(fstat(fd,&st)<0){close(fd);return -1;}uint32_t mode=(uint32_t)(st.st_mode&07777);if(!S_ISREG(st.st_mode)||(uint64_t)st.st_dev!=t->dev||(uint64_t)st.st_ino!=t->ino||(uint64_t)st.st_size!=t->size||st.st_nlink!=1||(uint32_t)st.st_uid!=t->uid||(uint32_t)st.st_gid!=t->gid||(mode!=0400U&&mode!=t->mode)){close(fd);errno=ESTALE;return -1;}sha_fd(fd,hash);if(strcmp(hash,t->sha)){close(fd);errno=ESTALE;return -1;}return fd;}
static int open_exact_crash_recovery(int d,const char *name,Target *t){int fd=open_beneath(d,name,O_RDONLY|O_NOFOLLOW);if(fd<0)return -1;struct stat st;char hash[65];if(fstat(fd,&st)<0){close(fd);return -1;}uint32_t mode=(uint32_t)(st.st_mode&07777);if(!S_ISREG(st.st_mode)||(uint64_t)st.st_dev!=t->dev||(uint64_t)st.st_ino!=t->ino||(uint64_t)st.st_size!=t->size||(st.st_nlink!=1&&st.st_nlink!=2)||(uint32_t)st.st_uid!=t->uid||(uint32_t)st.st_gid!=t->gid||(mode!=0400U&&mode!=t->mode)){close(fd);errno=ESTALE;return -1;}sha_fd(fd,hash);if(strcmp(hash,t->sha)){close(fd);errno=ESTALE;return -1;}return fd;}
static void split_path(const char *path,char parent[PATH_CAP+1],char name[256]){const char *slash=strrchr(path,'/');const char *base=slash?slash+1:path;size_t bn=strlen(base),pn=slash?(size_t)(slash-path):0;if(!bn||bn>=256||pn>PATH_CAP)die("invalid target basename");memcpy(name,base,bn+1);if(!slash)strcpy(parent,".");else{memcpy(parent,path,pn);parent[pn]=0;}}
static int open_parent_path(int base,const char *path){if(!strcmp(path,"."))return openat(base,".",O_RDONLY|O_DIRECTORY|O_CLOEXEC);int fd=open_beneath(base,path,O_RDONLY|O_DIRECTORY);if(fd<0)die("target parent unavailable or symlinked");return fd;}
static int mkdir_chain(int base,const char *path){int cur=openat(base,".",O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(cur<0)die("directory descriptor duplication failed");if(!strcmp(path,"."))return cur;char copy[PATH_CAP+1];strcpy(copy,path);char *save=NULL,*part=strtok_r(copy,"/",&save);while(part){int created=0;if(mkdirat(cur,part,0700)<0){if(errno!=EEXIST){close(cur);die("quarantine directory create failed");}}else created=1;if(created&&fsync(cur)<0){close(cur);die("quarantine directory parent fsync failed");}int next=open_beneath(cur,part,O_RDONLY|O_DIRECTORY);if(next<0){close(cur);die("quarantine directory unsafe");}struct stat st;if(fstat(next,&st)<0||st.st_uid!=geteuid()||(st.st_mode&0777)!=0700){close(next);close(cur);die("quarantine directory metadata mismatch");}close(cur);cur=next;part=strtok_r(NULL,"/",&save);}return cur;}
static void journal(const char *state,size_t index){char row[160];int n=snprintf(row,sizeof row,"%s\t%zu\n",state,index);if(n<=0||(size_t)n>=sizeof row)die("journal framing failed");write_all(journal_fd,row,(size_t)n);if(fsync(journal_fd)<0)die("journal fsync failed");}
static void write_bound_text(const char *name,const char *text,size_t bytes){int fd=openat(qroot_fd,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0400);if(fd<0)die("bound transaction manifest create failed");write_all(fd,text,bytes);if(fsync(fd)<0){close(fd);die("bound transaction manifest fsync failed");}close(fd);}
static void verify_bound_text(const char *name,const char *text,size_t bytes){int fd=openat(qroot_fd,name,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(fd<0)die("persisted transaction manifest unavailable");struct stat st;if(fstat(fd,&st)<0||!S_ISREG(st.st_mode)||st.st_uid!=geteuid()||(st.st_mode&07777)!=0400||(size_t)st.st_size!=bytes){close(fd);die("persisted transaction manifest metadata drift");}char *raw=malloc(bytes+1);if(!raw){close(fd);die("allocation failed");}size_t used=0;while(used<bytes){ssize_t n=read(fd,raw+used,bytes-used);if(n<0&&errno==EINTR)continue;if(n<=0){free(raw);close(fd);die("persisted transaction manifest read failed");}used+=(size_t)n;}char extra;if(read(fd,&extra,1)!=0||memcmp(raw,text,bytes)){free(raw);close(fd);die("persisted transaction manifest substitution");}free(raw);close(fd);}

static void parse_manifest(const char *hex,const char *expected){size_t hn=strlen(hex);if(!hn||hn>MANIFEST_CAP*2||hn%2)die("invalid manifest encoding");size_t n=hn/2;char *raw=malloc(n+1);if(!raw)die("allocation failed");for(size_t i=0;i<n;i++){int a=nibble(hex[i*2]),b=nibble(hex[i*2+1]);if(a<0||b<0)die("invalid manifest hex");raw[i]=(char)((a<<4)|b);if(!raw[i])die("manifest contains NUL");}raw[n]=0;char digest[65];sha_bytes(raw,n,digest);if(strcmp(digest,expected))die("manifest SHA-256 mismatch");char *save_line=NULL,*line=strtok_r(raw,"\n",&save_line),last[PATH_CAP+1]="";while(line){if(target_count>=TARGET_CAP)die("target cardinality cap");char *fields[8],*save_field=NULL,*field=strtok_r(line,"\t",&save_field);size_t f=0;while(field&&f<8){fields[f++]=field;field=strtok_r(NULL,"\t",&save_field);}if(f!=8||field)die("manifest field cardinality");size_t ph=strlen(fields[0]);if(!ph||ph>PATH_CAP*2||ph%2||!valid_hex(fields[1],64))die("manifest target identity");Target *t=&targets[target_count];size_t pn=ph/2;if(pn>PATH_CAP)die("target path cap");for(size_t i=0;i<pn;i++){int a=nibble(fields[0][i*2]),b=nibble(fields[0][i*2+1]);if(a<0||b<0)die("target path hex");t->path[i]=(char)((a<<4)|b);if(!t->path[i]||((unsigned char)t->path[i]<0x20))die("target path control byte");}t->path[pn]=0;if(t->path[0]=='/'||strstr(t->path,"//")||!strcmp(t->path,".")||strstr(t->path,"../")||strstr(t->path,"/../")||pn>=3&&!strcmp(t->path+pn-3,"/.."))die("target escapes root");if(last[0]&&strcmp(last,t->path)>=0)die("targets are not unique canonical lexical order");strcpy(last,t->path);strcpy(t->sha,fields[1]);t->size=number(fields[2],"size");uint64_t mode=number(fields[3],"mode"),uid=number(fields[4],"uid"),gid=number(fields[5],"gid");t->dev=number(fields[6],"dev");t->ino=number(fields[7],"ino");if(mode>07777||uid>UINT32_MAX||gid>UINT32_MAX||!t->ino)die("manifest metadata bounds");t->mode=(uint32_t)mode;t->uid=(uint32_t)uid;t->gid=(uint32_t)gid;t->live_parent=t->quarantine_parent=t->object_fd=-1;t->moved=0;target_count++;line=strtok_r(NULL,"\n",&save_line);}free(raw);if(!target_count)die("empty target set");}

static void parse_parent_manifest(const char *hex,const char *expected){
    size_t hn=strlen(hex);if(!hn||hn>MANIFEST_CAP*2||hn%2)die("invalid parent manifest encoding");
    size_t n=hn/2;char *raw=malloc(n+1);if(!raw)die("allocation failed");
    for(size_t i=0;i<n;i++){int a=nibble(hex[i*2]),b=nibble(hex[i*2+1]);if(a<0||b<0)die("invalid parent manifest hex");raw[i]=(char)((a<<4)|b);if(!raw[i])die("parent manifest contains NUL");}raw[n]=0;
    char digest[65];sha_bytes(raw,n,digest);if(strcmp(digest,expected))die("parent manifest SHA-256 mismatch");
    size_t index=0;char *save_line=NULL,*line=strtok_r(raw,"\n",&save_line);
    while(line){if(index>=target_count)die("parent manifest cardinality");char *tab=strchr(line,'\t');if(!tab||strchr(tab+1,'\t'))die("parent manifest fields");*tab=0;targets[index].parent_dev=number(line,"parent device");targets[index].parent_ino=number(tab+1,"parent inode");if(!targets[index].parent_dev||!targets[index].parent_ino)die("parent manifest identity");index++;line=strtok_r(NULL,"\n",&save_line);}
    free(raw);if(index!=target_count)die("parent manifest cardinality");
}

static void open_context(const char *root,uint64_t expected_dev,uint64_t expected_ino,const char *operation,int create,uint64_t expected_qdev,uint64_t expected_qino){
    root_fd=open_abs(root,O_RDONLY|O_DIRECTORY);struct stat rst;
    if(fstat(root_fd,&rst)<0||!S_ISDIR(rst.st_mode)||(uint64_t)rst.st_dev!=expected_dev||(uint64_t)rst.st_ino!=expected_ino)die("canonical root identity drift");
    root_device=(uint64_t)rst.st_dev;
    char parent_path[PATH_CAP+1];strcpy(parent_path,root);char *slash=strrchr(parent_path,'/');if(!slash||slash==parent_path)die("root parent policy");*slash=0;
    parent_fd=open_abs(parent_path,O_RDONLY|O_DIRECTORY);struct stat pst;
    if(fstat(parent_fd,&pst)<0||!S_ISDIR(pst.st_mode)||pst.st_uid!=geteuid()||(pst.st_mode&0022))die("root parent trust policy");
    snprintf(qname,sizeof qname,".wapp-security-exact-file-%s",operation);
    if(create){if(expected_qdev||expected_qino)die("apply cannot accept preexisting quarantine identity");if(mkdirat(parent_fd,qname,0700)<0)die(errno==EEXIST?"quarantine destination collision":"quarantine root create failed");if(fsync(parent_fd)<0)die("quarantine root parent fsync failed");}
    qroot_fd=open_beneath(parent_fd,qname,O_RDONLY|O_DIRECTORY);if(qroot_fd<0)die("quarantine root unavailable");struct stat qst;
    if(fstat(qroot_fd,&qst)<0||qst.st_uid!=geteuid()||(qst.st_mode&0777)!=0700||(uint64_t)qst.st_dev!=expected_dev)die("quarantine root policy mismatch");
    if(!create&&((uint64_t)qst.st_dev!=expected_qdev||(uint64_t)qst.st_ino!=expected_qino))die("quarantine root identity drift");
    if(create){if(mkdirat(qroot_fd,"files",0700)<0)die("quarantine files root create failed");if(fsync(qroot_fd)<0)die("quarantine files root parent fsync failed");}
    files_fd=open_beneath(qroot_fd,"files",O_RDONLY|O_DIRECTORY);if(files_fd<0)die("quarantine files root unavailable");
}
static void prepare_live(void){for(size_t i=0;i<target_count;i++){Target *t=&targets[i];char pp[PATH_CAP+1];split_path(t->path,pp,t->live_name);t->live_parent=open_parent_path(root_fd,pp);struct stat pst;if(fstat(t->live_parent,&pst)<0||(uint64_t)pst.st_dev!=t->parent_dev||(uint64_t)pst.st_ino!=t->parent_ino||(uint64_t)pst.st_dev!=t->dev||t->dev!=root_device)die("target parent identity or filesystem drift");t->object_fd=open_exact_at(t->live_parent,t->live_name,t,0);if(t->object_fd<0)die("target exact prestate drift");for(size_t j=0;j<i;j++)if(t->dev==targets[j].dev&&t->ino==targets[j].ino)die("duplicate physical target");}}
static void prepare_quarantine(void){for(size_t i=0;i<target_count;i++){Target *t=&targets[i];char pp[PATH_CAP+1];split_path(t->path,pp,t->quarantine_name);t->quarantine_parent=mkdir_chain(files_fd,pp);if(!absent_at(t->quarantine_parent,t->quarantine_name))die("quarantine destination collision");}}
static int restore_one(Target *t){if(!absent_at(t->live_parent,t->live_name))return -1;int fd=open_exact_quarantine_recovery(t->quarantine_parent,t->quarantine_name,t);if(fd<0)return -1;if(fchmod(fd,t->mode)<0||fsync(fd)<0){close(fd);return -1;}close(fd);if(syscall(SYS_renameat2,t->quarantine_parent,t->quarantine_name,t->live_parent,t->live_name,RENAME_NOREPLACE)<0)return -1;if(fsync(t->live_parent)<0)return -1;test_crash("restore_after_destination_fsync");if(fsync(t->quarantine_parent)<0)return -1;fd=open_exact_at(t->live_parent,t->live_name,t,0);if(fd<0)return -1;close(fd);return absent_at(t->quarantine_parent,t->quarantine_name)?0:-1;}
static void apply_transaction(const char *manifest_hex,size_t manifest_hex_len,const char *parent_hex,size_t parent_hex_len,const char *manifest_sha){
    prepare_live();prepare_quarantine();write_bound_text("manifest.hex",manifest_hex,manifest_hex_len);write_bound_text("parent-manifest.hex",parent_hex,parent_hex_len);if(fsync(qroot_fd)<0)die("transaction manifest directory fsync failed");journal_fd=openat(qroot_fd,"journal",O_WRONLY|O_CREAT|O_EXCL|O_APPEND|O_NOFOLLOW|O_CLOEXEC,0400);if(journal_fd<0)die("journal create failed");if(fsync(qroot_fd)<0)die("journal directory fsync failed");journal("BEGIN",target_count);
    for(size_t i=0;i<target_count;i++){Target *t=&targets[i];struct stat held,named;if(fstat(t->object_fd,&held)<0||fstatat(t->live_parent,t->live_name,&named,AT_SYMLINK_NOFOLLOW)<0||held.st_dev!=named.st_dev||held.st_ino!=named.st_ino)goto compensate;char hash[65];sha_fd(t->object_fd,hash);if(strcmp(hash,t->sha))goto compensate;if(syscall(SYS_renameat2,t->live_parent,t->live_name,t->quarantine_parent,t->quarantine_name,RENAME_NOREPLACE)<0)goto compensate;t->moved=1;mutation_started=1;if(fsync(t->quarantine_parent)<0)goto compensate;test_crash("apply_after_destination_fsync");if(fsync(t->live_parent)<0)goto compensate;int fd=open_beneath(t->quarantine_parent,t->quarantine_name,O_RDONLY|O_NOFOLLOW);if(fd<0||fchmod(fd,0400)<0||fsync(fd)<0){if(fd>=0)close(fd);goto compensate;}close(fd);fd=open_exact_at(t->quarantine_parent,t->quarantine_name,t,1);if(fd<0||!absent_at(t->live_parent,t->live_name)){if(fd>=0)close(fd);goto compensate;}close(fd);journal("MOVED",i);}
    journal("COMMITTED",target_count);struct stat qst;if(fstat(qroot_fd,&qst)<0)partial("quarantine root receipt unavailable");mutation_started=0;printf("WAPP_EXACT_FILE_STATE_V1\tQUARANTINED_EXACT\t%zu\t%s\t%llu\t%llu\n",target_count,manifest_sha,(unsigned long long)qst.st_dev,(unsigned long long)qst.st_ino);return;
compensate:
    for(size_t j=target_count;j>0;j--){Target *t=&targets[j-1];if(t->moved&&restore_one(t)<0)partial("automatic compensation failed");}
    mutation_started=0;journal("COMPENSATED",target_count);die("mutation failed; exact compensation verified");
}
static void open_quarantine_targets(void){for(size_t i=0;i<target_count;i++){Target *t=&targets[i];char live_pp[PATH_CAP+1],qpp[PATH_CAP+1];split_path(t->path,live_pp,t->live_name);split_path(t->path,qpp,t->quarantine_name);t->live_parent=open_parent_path(root_fd,live_pp);struct stat pst;if(fstat(t->live_parent,&pst)<0||(uint64_t)pst.st_dev!=t->parent_dev||(uint64_t)pst.st_ino!=t->parent_ino)die("follow-up target parent identity drift");t->quarantine_parent=open_parent_path(files_fd,qpp);struct stat qpst;if(fstat(t->quarantine_parent,&qpst)<0||(uint64_t)qpst.st_dev!=root_device)die("follow-up quarantine parent filesystem drift");}}
static void observe_state(int want_quarantine){open_quarantine_targets();for(size_t i=0;i<target_count;i++){Target *t=&targets[i];int present=want_quarantine?t->quarantine_parent:t->live_parent;const char *pn=want_quarantine?t->quarantine_name:t->live_name;int absent=want_quarantine?t->live_parent:t->quarantine_parent;const char *an=want_quarantine?t->live_name:t->quarantine_name;if(!absent_at(absent,an))partial("unexpected object occupies absent side");int fd=open_exact_at(present,pn,t,want_quarantine);if(fd<0)partial("expected exact object unavailable");close(fd);}printf("WAPP_EXACT_FILE_STATE_V1\t%s\t%zu\n",want_quarantine?"QUARANTINED_EXACT":"ORIGINAL_EXACT",target_count);}
static void rollback_transaction(void){open_quarantine_targets();for(size_t i=0;i<target_count;i++){Target *t=&targets[i];if(!absent_at(t->live_parent,t->live_name))partial("rollback source collision");int fd=open_exact_at(t->quarantine_parent,t->quarantine_name,t,1);if(fd<0)partial("rollback quarantine drift");close(fd);}for(size_t i=target_count;i>0;i--)if(restore_one(&targets[i-1])<0)partial("rollback partial or diverged");printf("WAPP_EXACT_FILE_STATE_V1\tORIGINAL_EXACT\t%zu\n",target_count);}
static void reconcile_rollback(void){
    open_quarantine_targets();
    for(size_t i=0;i<target_count;i++){
        Target *t=&targets[i];int live_fd=open_exact_crash_recovery(t->live_parent,t->live_name,t);int q_fd=open_exact_crash_recovery(t->quarantine_parent,t->quarantine_name,t);
        if(live_fd>=0&&q_fd>=0){struct stat live,q;if(fstat(live_fd,&live)<0||fstat(q_fd,&q)<0||live.st_dev!=q.st_dev||live.st_ino!=q.st_ino||live.st_nlink!=2||q.st_nlink!=2){close(live_fd);close(q_fd);partial("duplicate non-identical object on both sides");}if(fchmod(live_fd,t->mode)<0||fsync(live_fd)<0){close(live_fd);close(q_fd);partial("duplicate crash state mode recovery failed");}close(live_fd);close(q_fd);if(unlinkat(t->quarantine_parent,t->quarantine_name,0)<0||fsync(t->quarantine_parent)<0)partial("duplicate crash state link recovery failed");live_fd=open_exact_at(t->live_parent,t->live_name,t,0);if(live_fd<0||!absent_at(t->quarantine_parent,t->quarantine_name)){if(live_fd>=0)close(live_fd);partial("duplicate crash state verification failed");}close(live_fd);t->moved=0;continue;}
        if(live_fd<0&&q_fd<0)partial("target is neither exact original nor exact quarantine");
        if(live_fd>=0){if(fchmod(live_fd,t->mode)<0||fsync(live_fd)<0){close(live_fd);partial("live crash state mode recovery failed");}close(live_fd);if(!absent_at(t->quarantine_parent,t->quarantine_name))partial("non-exact quarantine collision");live_fd=open_exact_at(t->live_parent,t->live_name,t,0);if(live_fd<0)partial("live crash state verification failed");close(live_fd);t->moved=0;}
        else{close(q_fd);if(!absent_at(t->live_parent,t->live_name))partial("non-exact source collision");t->moved=1;}
    }
    for(size_t i=target_count;i>0;i--)if(targets[i-1].moved&&restore_one(&targets[i-1])<0)partial("reconciliation rollback diverged");
    printf("WAPP_EXACT_FILE_STATE_V1\tORIGINAL_EXACT_RECONCILED\t%zu\n",target_count);
}
static void cleanup(void){for(size_t i=0;i<target_count;i++){if(targets[i].object_fd>=0)close(targets[i].object_fd);if(targets[i].live_parent>=0)close(targets[i].live_parent);if(targets[i].quarantine_parent>=0)close(targets[i].quarantine_parent);}if(journal_fd>=0)close(journal_fd);if(files_fd>=0)close(files_fd);if(qroot_fd>=0)close(qroot_fd);if(parent_fd>=0)close(parent_fd);if(root_fd>=0)close(root_fd);}

int main(int argc,char **argv){
    if(argc!=14)die("invalid bounded invocation");
    const char *mode=argv[1],*root=argv[2],*operation=argv[3],*manifest_sha=argv[6],*manifest_hex=argv[7],*parent_sha=argv[8],*parent_hex=argv[9],*runtime=argv[12],*contract=argv[13];
    if(strcmp(mode,"apply")&&strcmp(mode,"observe-quarantined")&&strcmp(mode,"rollback")&&strcmp(mode,"reconcile-rollback")&&strcmp(mode,"observe-original"))die("invalid bounded mode");
    if(!valid_root(root)||!valid_hex(operation,32)||!valid_hex(manifest_sha,64)||!valid_hex(parent_sha,64)||strcmp(contract,"QUARANTINE_EXACT_FILE_V1")||strncmp(runtime,"loader=HUMAN_OPERATOR_EMERGENCY_NATIVE_EXACT_FILE_V1|",53))die("invalid bounded identity");
    uint64_t root_dev=number(argv[4],"root device"),root_ino=number(argv[5],"root inode"),qdev=number(argv[10],"quarantine device"),qino=number(argv[11],"quarantine inode");
    struct rlimit files={256,256},memory={512U*1024U*1024U,512U*1024U*1024U};if(setrlimit(RLIMIT_NOFILE,&files)<0||setrlimit(RLIMIT_AS,&memory)<0)die("process limits unavailable");
    parse_manifest(manifest_hex,manifest_sha);parse_parent_manifest(parent_hex,parent_sha);open_context(root,root_dev,root_ino,operation,!strcmp(mode,"apply"),qdev,qino);
    if(strcmp(mode,"apply")){verify_bound_text("manifest.hex",manifest_hex,strlen(manifest_hex));verify_bound_text("parent-manifest.hex",parent_hex,strlen(parent_hex));}
    if(!strcmp(mode,"apply"))apply_transaction(manifest_hex,strlen(manifest_hex),parent_hex,strlen(parent_hex),manifest_sha);else if(!strcmp(mode,"observe-quarantined"))observe_state(1);else if(!strcmp(mode,"rollback"))rollback_transaction();else if(!strcmp(mode,"reconcile-rollback"))reconcile_rollback();else observe_state(0);cleanup();return 0;
}
#endif
