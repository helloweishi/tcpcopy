#ifndef  _LOG_H_INC
#define  _LOG_H_INC

#include <xcopy.h>

/*
 * priorities/facilities are encoded into a single 32-bit quantity, where the
 * bottom 3 bits are the priority (0-7) and the top 28 bits are the facility
 * (0-big number).  Both the priorities and the facilities map roughly
 * one-to-one to strings in the syslogd(8) source code.  This mapping is
 * included in this file.
 *
 * priorities (these are ordered)
 */
#define	PRI_EMERG	0	/* system is unusable */
#define	PRI_ALERT	1	/* action must be taken immediately */
#define	PRI_CRIT	2	/* critical conditions */
#define	PRI_ERR	       3	/* error conditions */
#define	PRI_WARN	4	/* warning conditions */
#define	PRI_NOTICE	5	/* normal but significant condition */
#define	PRI_INFO	6	/* informational */
#define	PRI_DEBUG	7	/* debug-level messages */

#define	LOG_PRIMASK	0x07	/* mask to extract priority part (internal) */
				/* extract priority */
#define	LOG_PRI(p)	((p) & LOG_PRIMASK)

/* facility codes */
#define	LOG_KERN	0	/* kernel messages */
#define	LOG_USER	1	/* random user-level messages */
#define	LOG_MAIL	2	/* mail system */
#define	LOG_DAEMON	3	/* system daemons */
#define	LOG_AUTH	    4	/* security/authorization messages */
#define	LOG_SYSLOG	    5	/* messages generated internally by syslogd */
#define	LOG_LPR		6	/* line printer subsystem */
#define	LOG_NEWS	    7	/* network news subsystem */

#define	CUR_FACMASK	0x07 /* mask to extract facility part (can change ,up to 28 bits)*/
#define   LOG_FAC(p)    (((p) >> 3) & CUR_FACMASK)

#define   LOG_MSG(fac,p)    (((fac) << 3) | (p))
#define   LOG_LEVEL(p)     LOG_MSG(LOG_USER,p)

#define	LOG_EMERG	LOG_LEVEL(PRI_EMERG)	
#define	LOG_ALERT	LOG_LEVEL(PRI_ALERT)		
#define	LOG_CRIT	LOG_LEVEL(PRI_CRIT)		
#define	LOG_ERR	LOG_LEVEL(PRI_ERR)		
#define	LOG_WARN	LOG_LEVEL(PRI_WARN)		
#define	LOG_NOTICE	LOG_LEVEL(PRI_NOTICE)		
#define	LOG_INFO	LOG_LEVEL(PRI_INFO)		
#define	LOG_DEBUG	LOG_LEVEL(PRI_DEBUG)	


  
typedef struct{
    uint16_t log_port;
    char log_addr[IP_ADDR_LEN];
    char* log_file;
 struct {
    uint8_t logtype:2, /* 0 none, 1 local,2 remote,3 both*/
              cyclelog:1,
              autopack:1,
              loglevel:4;
  }log_ct;

    long loglimit;                         
}tc_log_t;

extern  tc_log_t log_info;

int tc_log_init();
void tc_log_end();

void tc_log_info(unsigned int level, int err, const char *fmt, ...);
void tc_log_trace(unsigned int level, int err, int flag, struct iphdr *ip_header,
        struct tcphdr *tcp_header);

#if (TCPCOPY_DEBUG)

#define tc_log(level,err,fmt,...)   \
({  \
    do{ \
        if (LOG_PRI(level) <= log_info.log_ct.loglevel)   \
            tc_log_info(level,err,fmt,##__VA_ARGS__); \
    }while(0);  \
})
    
#define tc_log_debug_trace(level, err, flag, ip_header, tcp_header)          \
    tc_log_trace(level, err, flag, ip_header, tcp_header)

#else

#define tc_log(level,err,fmt,...)   do{}while(0)
#define tc_log_debug_trace(level, err, flag, ip_header, tcp_header) do{}while(0)

#endif /* TCPCOPY_DEBUG */

#endif /* _LOG_H_INC */


