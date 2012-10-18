#ifndef  _TCPCOPY_UTIL_H_INC
#define  _TCPCOPY_UTIL_H_INC

#include <xcopy.h>
#include <tcpcopy.h>

inline uint64_t get_key(uint32_t s_ip, uint16_t s_port);
inline uint16_t get_appropriate_port(uint16_t orig_port, uint16_t add);
uint16_t get_port_by_rand_addition(uint16_t orig_port);
uint16_t get_port_from_shift(uint16_t orig_port, uint16_t rand_port,
        int shift_factor);
ip_port_pair_mapping_t *get_test_pair(ip_port_pair_mappings_t *target,
        uint32_t ip, uint16_t port);
int check_pack_src(ip_port_pair_mappings_t *target, uint32_t ip, 
        uint16_t port, int src_flag);
unsigned char *copy_ip_packet(struct iphdr *ip_header);
unsigned short csum (unsigned short *packet, int pack_len);
unsigned short tcpcsum(unsigned char *iphdr, unsigned short *packet,
        int pack_len);
int tc_system(char *command);


typedef struct{
    char* str;
    union{
        void* value_pointer;
        void** value_ptr_to_ptr;
    }value;
#define value_pointer           value.value_pointer
#define value_ptr_to_ptr      value.value_ptr_to_ptr

    int type;
    int limit;
    char shift;
}config_setting;

#define CONFIG_ITEM(conf_item ,conf_setting ,item_type , length_limt) \
    {#conf_item ,&(conf_setting.conf_item) ,(item_type) ,(length_limt) ,-1},

#define CONFIG_ITEM_SINGLE(config_item ,item_type ,length_limit)    \
    {#config_item ,&(config_item) ,(item_type) ,(length_limit) , -1},

#define CONFIG_ITEM_BIT(config_item ,config_setting ,config_bit ,item_type ,length_limit ,shift)   \
    {#config_item ,&(config_setting.config_bit) ,(item_type) ,(length_limit) ,(shift)},
    
#define NULL_ITEM   {NULL ,NULL}

enum{
TYPE_CHAR_PTR = 0,
TYPE_UNSIGNED_INT,
TYPE_LONG,
TYPE_SIZE_T,
TYPE_UINT16_T,
TYPE_CHAR_ARRAY,
TYPE_UINT8_T,
TYPE_IPV4_ADDR,
};

int  tc_setting_from_conf(config_setting* config,char* config_file);

int is_valid_ipv4_addr(char* addr);
#endif   /* ----- #ifndef _TCPCOPY_UTIL_H_INC  ----- */

