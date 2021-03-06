#ifndef __TCPCOPY_H__
#define __TCPCOPY_H__ 


#define localhost (inet_addr("127.0.0.1"))

typedef struct {
    /* Online ip from the client perspective */
    uint32_t online_ip;
    uint32_t target_ip;
    uint16_t online_port;
    uint16_t target_port;
} ip_port_pair_mapping_t;


typedef struct {
    int                      num;
    ip_port_pair_mapping_t **mappings;
} ip_port_pair_mappings_t;


typedef struct xcopy_clt_settings {
    struct{
    unsigned int  do_daemonize:1,       /* Daemon flag */
                        replica_num:10,       /* Replicated number of each request */
                        max_rss:21;           /* Max memory size allowed for tcpcopy client(max size 2G) */
          }mix;

    uint16_t  mtu;               /* MTU sent to backend */
    uint16_t  session_timeout;   /* Max value for session timeout
                                           If it reaches this value, the session  will be removed */

    char         *raw_transfer;         /* Online_ip online_port target_ip
                                           target_port string */

    char         *pid_file;             /* Pid file */
    char         *conf_path;             /* Error log path */
#if (TCPCOPY_OFFLINE)
    char         *pcap_file;            /* Pcap file */
#endif
    uint16_t      rand_port_shifted;    /* Random port shifted */
    uint16_t      srv_port;             /* Server listening port */
    uint32_t      lo_tf_ip;             /* Ip address from localhost to
                                           (localhost transfered ip) */
#ifdef TCPCOPY_MYSQL_ADVANCED
    char         *user_pwd;             /* User password string for mysql */
#endif
    ip_port_pair_mappings_t transfer;   /* Transfered online_ip online_port
                                           target_ip target_port */
    int           multiplex_io;
    uint8_t  factor;             /* Port shift factor */ 

} xcopy_clt_settings;


extern int tc_raw_socket_out;
extern tc_event_loop_t event_loop;
extern xcopy_clt_settings clt_settings;

#include <tc_util.h>

#ifdef TCPCOPY_MYSQL_ADVANCED
#include <pairs.h>
#include <protocol.h>
#endif

#include <tc_manager.h>
#include <tc_session.h>
#include <tc_message_module.h>
#include <tc_packets_module.h>

#endif /* __TCPCOPY_H__ */
