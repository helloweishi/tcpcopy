#ifndef __INTERCEPT_H__
#define __INTERCEPT_H__

typedef struct passed_ip_addr_s {
    /* It allows 32 ip addresses passed through server firewall */
    uint32_t    ips[MAX_ALLOWED_IP_NUM];
    int         num;
} passed_ip_addr_t;


typedef struct xcopy_srv_settings {
    char             *raw_ip_list;      /* Raw ip list */
    char             *pid_file;         /* Pid file */
    char             *binded_ip;        /* Binded ip for security */
    char             *conf_path;         /* Error log path */
    size_t            hash_size;        /* Hash size for kinds of table */
    uint16_t          port;             /* TCP port number to listen on */
 struct {
    uint8_t      do_daemonize:1;   /* Daemon flag */
}daemon;   

    passed_ip_addr_t  passed_ips;       /* Passed ip list */
}xcopy_srv_settings;

extern xcopy_srv_settings srv_settings;

#include <tc_util.h>
#include <tc_delay.h>
#include <tc_interception.h>
#include <tc_router.h>

#endif /* __INTERCEPT_H__ */
