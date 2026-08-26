#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#if !defined(__linux__) || !defined(__x86_64__)
int main(void) {
    fputs("wapp-ephemeral-memfd-launcher: unsupported platform\n", stderr);
    return 78;
}
#else

#define HELPER_BYTES 93304U
#define HELPER_SHA256 "f1240b7a873033738c4fb23913706e73531c2be5667ff6b827f1d3c2f7dec047"

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
static void block(Sha256 *s,const unsigned char *p){uint32_t w[64],a,b,c,d,e,f,g,h,t1,t2;unsigned i;for(i=0;i<16;i++)w[i]=((uint32_t)p[i*4]<<24)|((uint32_t)p[i*4+1]<<16)|((uint32_t)p[i*4+2]<<8)|p[i*4+3];for(i=16;i<64;i++){uint32_t x=w[i-15],y=w[i-2];w[i]=(rotr(y,17)^rotr(y,19)^(y>>10))+w[i-7]+(rotr(x,7)^rotr(x,18)^(x>>3))+w[i-16];}a=s->h[0];b=s->h[1];c=s->h[2];d=s->h[3];e=s->h[4];f=s->h[5];g=s->h[6];h=s->h[7];for(i=0;i<64;i++){t1=h+(rotr(e,6)^rotr(e,11)^rotr(e,25))+((e&f)^((~e)&g))+K[i]+w[i];t2=(rotr(a,2)^rotr(a,13)^rotr(a,22))+((a&b)^(a&c)^(b&c));h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;}s->h[0]+=a;s->h[1]+=b;s->h[2]+=c;s->h[3]+=d;s->h[4]+=e;s->h[5]+=f;s->h[6]+=g;s->h[7]+=h;}
static void init(Sha256 *s){static const uint32_t H[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};memcpy(s->h,H,sizeof H);s->bits=0;s->used=0;}
static void update(Sha256 *s,const void *v,size_t n){const unsigned char *p=v;s->bits+=(uint64_t)n*8;while(n){size_t take=64-s->used;if(take>n)take=n;memcpy(s->block+s->used,p,take);s->used+=take;p+=take;n-=take;if(s->used==64){block(s,s->block);s->used=0;}}}
static void finish(Sha256 *s,unsigned char out[32]){unsigned i;s->block[s->used++]=0x80;if(s->used>56){while(s->used<64)s->block[s->used++]=0;block(s,s->block);s->used=0;}while(s->used<56)s->block[s->used++]=0;for(i=0;i<8;i++)s->block[63-i]=(unsigned char)(s->bits>>(8*i));block(s,s->block);for(i=0;i<8;i++){out[i*4]=(unsigned char)(s->h[i]>>24);out[i*4+1]=(unsigned char)(s->h[i]>>16);out[i*4+2]=(unsigned char)(s->h[i]>>8);out[i*4+3]=(unsigned char)s->h[i];}}
static void hex32(const unsigned char in[32],char out[65]){static const char H[]="0123456789abcdef";for(int i=0;i<32;i++){out[i*2]=H[in[i]>>4];out[i*2+1]=H[in[i]&15];}out[64]=0;}
static void die(const char *m){fprintf(stderr,"wapp-ephemeral-memfd-launcher: %s\n",m);exit(20);}
static int safe_text(const char *s,size_t cap){size_t n=strlen(s);if(!n||n>cap)return 0;for(size_t i=0;i<n;i++){unsigned char c=(unsigned char)s[i];if(c<0x21||c>0x7e)return 0;}return 1;}
static int valid_root(const char *p){if(!p||p[0]!='/'||p[1]=='\0'||strlen(p)>4096||p[strlen(p)-1]=='/'||strstr(p,"//"))return 0;for(const char *s=p+1;*s;){const char *e=strchr(s,'/');size_t n=e?(size_t)(e-s):strlen(s);if(!n||(n==1&&s[0]=='.')||(n==2&&s[0]=='.'&&s[1]=='.'))return 0;if(!e)break;s=e+1;}return 1;}
static int valid_hex(const char *s,size_t n){if(strlen(s)!=n)return 0;for(size_t i=0;i<n;i++)if(!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f')))return 0;return 1;}
static int valid_volatile_policy(const char *s){size_t n=strlen(s),items=0,start=0;if(!n||n>32768)return 0;for(size_t i=0;i<=n;i++)if(i==n||s[i]==','){size_t length=i-start;if(++items>64||length<4||(s[start]!='A'&&s[start]!='C'&&s[start]!='L')||s[start+1]!=':'||((length-2)&1))return 0;for(size_t j=start+2;j<i;j++)if(!((s[j]>='0'&&s[j]<='9')||(s[j]>='a'&&s[j]<='f')))return 0;start=i+1;}return 1;}
static void write_all(int fd,const unsigned char *p,size_t n){size_t off=0;while(off<n){ssize_t got=write(fd,p+off,n-off);if(got<0&&errno==EINTR)continue;if(got<=0)die("memfd write failed");off+=(size_t)got;}}

int main(int argc,char **argv){
  if((argc!=5&&argc!=6)||((!strcmp(argv[1],"inventory")||!strcmp(argv[1],"diagnostic"))&&argc!=5)||((!strcmp(argv[1],"rollback")||!strcmp(argv[1],"volatile-inventory"))&&argc!=6))die("invalid bounded invocation");
  if(strcmp(argv[1],"inventory")&&strcmp(argv[1],"diagnostic")&&strcmp(argv[1],"rollback")&&strcmp(argv[1],"volatile-inventory"))die("invalid bounded mode");
  if(!valid_root(argv[2])||!valid_hex(argv[3],64)||!safe_text(argv[4],512))die("invalid bounded identity");
  if(strstr(argv[4],"loader=DEGRADED_ASSURANCE_EPHEMERAL_BOOTSTRAP_V1|")!=argv[4]||!strstr(argv[4],"|helper_sha=" HELPER_SHA256 "|transport=sealed_memfd_execveat_v1"))die("runtime identity contract");
  if(argc==6&&!strcmp(argv[1],"rollback")&&(!valid_hex(argv[5],strlen(argv[5]))||strlen(argv[5])<2||strlen(argv[5])>8192||strlen(argv[5])%2))die("invalid selected target");
  if(argc==6&&!strcmp(argv[1],"volatile-inventory")&&!valid_volatile_policy(argv[5]))die("invalid volatile policy");
  struct rlimit files={64,64},memory={256U*1024U*1024U,256U*1024U*1024U};if(setrlimit(RLIMIT_NOFILE,&files)<0||setrlimit(RLIMIT_AS,&memory)<0)die("process limits unavailable");
  unsigned char *raw=malloc(HELPER_BYTES+1U);if(!raw)die("allocation failed");size_t used=0;for(;;){ssize_t n=read(STDIN_FILENO,raw+used,HELPER_BYTES+1U-used);if(n<0&&errno==EINTR)continue;if(n<0)die("helper read failed");if(n==0)break;used+=(size_t)n;if(used>HELPER_BYTES)die("helper byte cap");}if(used!=HELPER_BYTES)die("helper byte count mismatch");
  Sha256 sh;unsigned char digest[32];char actual[65];init(&sh);update(&sh,raw,used);finish(&sh,digest);hex32(digest,actual);if(strcmp(actual,HELPER_SHA256))die("helper SHA-256 mismatch");
  int fd=(int)syscall(SYS_memfd_create,"wapp-native-displaced-inventory",MFD_ALLOW_SEALING);if(fd<3)die("memfd_create unavailable");write_all(fd,raw,used);free(raw);if(fcntl(fd,F_ADD_SEALS,F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE)<0)die("memfd seal failed");int seals=fcntl(fd,F_GET_SEALS);if(seals<0||(seals&15)!=15)die("incomplete memfd seals");struct stat st;if(fstat(fd,&st)<0||!S_ISREG(st.st_mode)||(size_t)st.st_size!=HELPER_BYTES)die("sealed helper identity");
  char fd_text[32];snprintf(fd_text,sizeof fd_text,"%d",fd);char *child[9]={"wapp-native-displaced-inventory",argv[1],argv[2],argv[3],(char*)HELPER_SHA256,argv[4],fd_text,NULL,NULL};if(argc==6)child[7]=argv[5];char *envp[]={NULL};syscall(SYS_execveat,fd,"",child,envp,AT_EMPTY_PATH);die("execveat unavailable");return 20;
}
#endif
