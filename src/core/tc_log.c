
#include <xcopy.h>
#include "tc_util.h"

static FILE* log_f = NULL;
static int remote_fd = -1;

#define CMD_LEN     512

tc_log_t log_info = {
    .log_port = 514,
    .log_addr =
    {
        [0] = '1',
        [1] = '2',
        [2] = '7',
        [3] = '.',
        [4] = '0',
        [5] = '.',
        [6] = '0',
        [7] = '.',
        [8] = '1'
     },
    .log_ct = 
    {
        .logtype = 0,
        .cyclelog = 0,
        .autopack = 0,
        .loglevel = PRI_EMERG
    }
};

static char *tc_log_dir = NULL;
static struct sockaddr_in remoteaddr;

static char* tc_log_pris[] = {
  [PRI_EMERG]     =  "EMERG",
  [PRI_ALERT]      =  "ALERT",
  [PRI_CRIT]        =  "CRIT", 
  [PRI_ERR]          =  "ERROR", 
  [PRI_WARN]      =  "WARN", 
  [PRI_NOTICE]    =  "NOTICE", 
  [PRI_INFO]        =  "INFO", 
  [PRI_DEBUG]     =  "DEBUG"
};

static char* tc_log_fac[] = {
  [LOG_KERN]       =  "KERN",
  [LOG_USER]       =  "USER",
  [LOG_MAIL]        =  "MAIL", 
  [LOG_DAEMON]   =  "DAEMON", 
  [LOG_AUTH]        =  "AUTH", 
  [LOG_SYSLOG]    =  "SYSLOG", 
  [LOG_LPR]          =  "LPR", 
  [LOG_NEWS]       =  "NEWS"
};

int
tc_log_init()
{
    if (log_info.log_ct.logtype & 1)
    {
        if (log_info.log_file == NULL){
            log_info.log_file = "error.log";
        }
        else
        {
            char *last_slash = strrchr(log_info.log_file,'/');
            if (last_slash != NULL)
            {
                unsigned int dir_len = (last_slash - log_info.log_file) + 2;
                if ((tc_log_dir = (char*)malloc(dir_len)) != NULL)
                {
                    char cmd[CMD_LEN] = {0};
                    
                    snprintf(tc_log_dir,dir_len,"%s",log_info.log_file);
                    snprintf(cmd,CMD_LEN,"mkdir -p %s",tc_log_dir);
                    tc_system(cmd);
                }
            }
        }
        
        log_f = fopen(log_info.log_file,"w+");

        if (log_f == NULL) {
            fprintf(stderr, "Open log file error: %s\n", strerror(errno));
        }
    }

    if (log_info.log_ct.logtype & 2)
    {
        memset(&remoteaddr,0,sizeof(struct sockaddr_in));
        remote_fd = socket(AF_INET,SOCK_DGRAM,0);
        if(remote_fd < 0){
             fprintf(stderr, "Create socket  error: %s\n", strerror(errno));
        }
        
       remoteaddr.sin_family = AF_INET;
	inet_aton(log_info.log_addr,&remoteaddr.sin_addr);
	remoteaddr.sin_port = htons(log_info.log_port);
    }
    
    return 0;
}

void
tc_log_end()
{
    if (log_f != NULL) {
        fclose(log_f);
    }
    
    if(remote_fd != -1){
        close(remote_fd);
    }
        
    log_f = NULL;
    remote_fd = -1;
}

#define BUF_LEN 2048
#define LOGLEVEL_LEN 16

static void 
tc_local_log(char *logstr,char *loglevel)
{
    char buffer[BUF_LEN] = {0};
    int n = 0;
    if (logstr == NULL || loglevel == NULL){
        return;
    }
     
    n = snprintf(buffer,BUF_LEN,"%s %14s %s\n",tc_error_log_time,loglevel,logstr);
    if (n < 0){
        return;
    }
    
    fwrite(buffer,sizeof(char), n,log_f);

    if ((log_info.log_ct.autopack || log_info.log_ct.cyclelog) && (log_info.loglimit > 0))
    {
        (void)fseek(log_f,0,SEEK_END);
        long size = ftell(log_f);
        
        if (log_info.loglimit <= size)
        {
            if (log_info.log_ct.autopack)
            {
                char cmd[CMD_LEN] = {0};
                if (tc_log_dir != NULL){
                    snprintf(cmd,CMD_LEN,"cp -rf %s %s%s",log_info.log_file,tc_log_dir,tc_generator_time_file());
                } else {
                    snprintf(cmd,CMD_LEN,"cp -rf %s %s",log_info.log_file,tc_generator_time_file());
                }
                tc_system(cmd);
                
                fseek(log_f,0,SEEK_SET);
                if (!log_info.log_ct.cyclelog){
                   ftruncate(fileno(log_f),0);
                }
                return;
            }
            
            if (log_info.log_ct.cyclelog){
                fseek(log_f,0,SEEK_SET);
            }
            return;
        }
    }
}

static void tc_remote_log(char *logstr,int level)
{
    char buffer[BUF_LEN] = {0};
    int n = 0,count = 0;
    if (logstr == NULL){
        return;
    }
    
    n = snprintf(buffer,BUF_LEN,"<%d> %s",level,logstr);
    if (n < 0){
        return;
    }

   while((-1 == sendto(remote_fd,buffer,n,0,(struct sockaddr*)&remoteaddr,sizeof(remoteaddr)))
                && errno == EINTR
                && ++count <= 3)
                usleep(500);
    
}

void
tc_log_info(unsigned int level, int err, const char *fmt, ...)
{
    char            buffer[BUF_LEN], *p,*end;
    size_t          n;
    va_list         args;
  //  char loglevel[LOGLEVEL_LEN] = {0};

    if (log_f == NULL && remote_fd == -1) {
        return;
    }

#if (TCPCOPY_DEBUG)
    tc_time_update();
#endif

    p = buffer;
    end = &buffer[BUF_LEN - 1];

    va_start(args, fmt);
    n = vsnprintf(p,end - p, fmt, args);
    va_end(args);

    if (n < 0) {
        return;
    }

    p += n;

    if (err > 0) {
        n = snprintf(p,end - p, " (%s)", strerror(err));
        if (n < 0) {
            return;
        }
    }
 #if 0   
    if (log_f != NULL){
        snprintf(loglevel ,LOGLEVEL_LEN ,"%s.%s:",tc_log_fac[LOG_FAC(level)] ,tc_log_pris[LOG_PRI(level)]);
        tc_local_log(buffer ,loglevel);
    }
#endif    
    if (remote_fd != -1){
        tc_remote_log(buffer,level);
    }
    
}

void
tc_log_trace(unsigned int level, int err, int flag, struct iphdr *ip_header,
        struct tcphdr *tcp_header)
{
    char           *tmp_buf, src_ip[1024], dst_ip[1024];
    uint16_t        window;
    uint32_t        pack_size;
    unsigned int    seq, ack_seq;
    struct in_addr  src_addr, dst_addr;

    src_addr.s_addr = ip_header->saddr;
    tmp_buf = inet_ntoa(src_addr);
    strcpy(src_ip, tmp_buf);

    dst_addr.s_addr = ip_header->daddr;
    tmp_buf = inet_ntoa(dst_addr);
    strcpy(dst_ip, tmp_buf);

    pack_size = ntohs(ip_header->tot_len);
    seq = ntohl(tcp_header->seq);
    ack_seq = ntohl(tcp_header->ack_seq);

    /* Strange here, not using ntohs */
    window = tcp_header->window;

    if (BACKEND_FLAG == flag) {
        tc_log_info(level, err,
                    "from bak:%s:%u-->%s:%u,len %u,seq=%u,ack=%u,win:%u",
                    src_ip, ntohs(tcp_header->source), dst_ip,
                    ntohs(tcp_header->dest), pack_size, seq,
                    ack_seq, window);

    } else if (CLIENT_FLAG == flag) {
        tc_log_info(level, err,
                    "recv clt:%s:%u-->%s:%u,len %u,seq=%u,ack=%u,win:%u",
                    src_ip, ntohs(tcp_header->source), dst_ip,
                    ntohs(tcp_header->dest), pack_size, seq,
                    ack_seq, window);

    } else if (TO_BAKEND_FLAG == flag) {
        tc_log_info(level, err,
                    "to bak:%s:%u-->%s:%u,len %u,seq=%u,ack=%u,win:%u",
                    src_ip, ntohs(tcp_header->source), dst_ip,
                    ntohs(tcp_header->dest), pack_size, seq,
                    ack_seq, window);

    } else if (FAKED_CLIENT_FLAG == flag) {
        tc_log_info(level, err,
                    "fake clt:%s:%u-->%s:%u,len %u,seq=%u,ack=%u,win:%u",
                    src_ip, ntohs(tcp_header->source), dst_ip,
                    ntohs(tcp_header->dest), pack_size, seq,
                    ack_seq, window);

    } else if (UNKNOWN_FLAG == flag) {
        tc_log_info(level, err,
                    "unkown packet:%s:%u-->%s:%u,len %u,seq=%u,ack=%u",
                    src_ip, ntohs(tcp_header->source), dst_ip,
                    ntohs(tcp_header->dest), pack_size,
                    seq, ack_seq);

    } else{
        tc_log_info(level, err,
                    "strange %s:%u-->%s:%u,length %u,seq=%u,ack=%u",
                    src_ip, ntohs(tcp_header->source), dst_ip,
                    ntohs(tcp_header->dest), pack_size,
                    seq, ack_seq);
    }
}

