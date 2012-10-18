
#include <xcopy.h>
#include <tcpcopy.h>

inline uint64_t
get_key(uint32_t ip, uint16_t port)
{
    uint64_t value = ((uint64_t)ip) << 16;

    value += port;

    return value;
}

inline uint16_t
get_appropriate_port(uint16_t orig_port, uint16_t add)
{
    uint16_t dest_port = orig_port;

    if (dest_port < (65536 - add)) {
        dest_port += add;
    } else {
        dest_port  = 1024 + add;
    }

    return dest_port;
}

static unsigned int seed = 0;

uint16_t
get_port_by_rand_addition(uint16_t orig_port)
{
    struct timeval  tp;
    uint16_t        port_add;

    if (0 == seed) {    
        gettimeofday(&tp, NULL);
        seed = tp.tv_usec;
    }    
    port_add = (uint16_t)(4096*(rand_r(&seed)/(RAND_MAX + 1.0)));
    port_add = port_add + 32768;

    return get_appropriate_port(ntohs(orig_port), port_add);
}

uint16_t
get_port_from_shift(uint16_t orig_port, uint16_t rand_port, int shift_factor)
{
    uint16_t        port_add;

    port_add = (shift_factor << 11) + rand_port;

    return get_appropriate_port(ntohs(orig_port), port_add);
}

ip_port_pair_mapping_t *
get_test_pair(ip_port_pair_mappings_t *transfer, uint32_t ip, uint16_t port)
{
    int                     i;
    ip_port_pair_mapping_t *pair, **mappings;

    pair     = NULL;
    mappings = transfer->mappings;
    for (i = 0; i < transfer->num; i++) {
        pair = mappings[i];
        if (ip == pair->online_ip && port == pair->online_port) {
            return pair;
        }else if(pair->online_ip == 0 && port == pair->online_port) {
            return pair;
        }
    }
    return NULL;
}

int
check_pack_src(ip_port_pair_mappings_t *transfer, uint32_t ip,
        uint16_t port, int src_flag)
{
    int                     i, ret;
    ip_port_pair_mapping_t *pair, **mappings;

    ret = UNKNOWN;
    mappings = transfer->mappings;

    for (i = 0; i < transfer->num; i++) {

        pair = mappings[i];
        if (CHECK_DEST == src_flag) {
            /* We are interested in INPUT raw socket */
            if (ip == pair->online_ip && port == pair->online_port) {
                ret = LOCAL;
                break;
            } else if (0 == pair->online_ip && port == pair->online_port) {
                ret = LOCAL;
                break;
            }
        } else if (CHECK_SRC == src_flag) {
            if (ip == pair->target_ip && port == pair->target_port) {
                ret = REMOTE;
                break;
            }
        }
    }

    return ret;
}

unsigned char *
copy_ip_packet(struct iphdr *ip_header)
{
    uint16_t       tot_len = ntohs(ip_header->tot_len);
    unsigned char *data    = (unsigned char *)malloc(tot_len);

    if (NULL != data) {    
        memcpy(data, ip_header, tot_len);
    }    

    return data;
}

unsigned short
csum(unsigned short *packet, int pack_len) 
{ 
    register unsigned long sum = 0; 

    while (pack_len > 1) {
        sum += *(packet++); 
        pack_len -= 2; 
    } 
    if (pack_len > 0) {
        sum += *(unsigned char *)packet; 
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16); 
    }

    return (unsigned short) ~sum; 
} 


#define MULTICAST_PREFIX	0xE0
#define BROADCAST_SUFFIX  0xFF
#define IP_NUMBER_CHECK(str,num)	\
({	\
	while((*(str) != '\0') && (*(str) != '.'))	\
	{	\
	    if(*(str) > '9' || *(str) < '0')	\
		return 0;	\
	    (num) = (num)*10 + (*(str) - '0');	\
	    if((num) > 0xFF)		\
		return 0; 	\
	    ++(str);		\
	}	\
	if(*(str) != '\0')	\
	    ++(str);		\
})

int 
is_valid_ipv4_addr(char* addr)
{
    unsigned long int num[4] = {0,0,0,0};
    char* dot = addr;
	
    if (dot == NULL)
        return 0;
	
    IP_NUMBER_CHECK(dot,num[0]);
    IP_NUMBER_CHECK(dot,num[1]);
    IP_NUMBER_CHECK(dot,num[2]);
    IP_NUMBER_CHECK(dot,num[3]);
	
/*
* exclude 0.x.x.x , above multicast  address, and broadcast address
*/
    if (num[0] >= MULTICAST_PREFIX || num[0] == 0
	|| num[3] == 0 || num[3] == BROADCAST_SUFFIX)
	return 0;

return 1;
}

#define VALID_CHAR(c)   \
({  \
    char tmp = (c);     \
    int ret = 0;    \
    if ((tmp >= '0' && tmp <= '9')      \
        ||(tmp >= 'a' && tmp <= 'z')    \
        ||(tmp >= 'A' && tmp <= 'Z')    \
        ||(tmp == '#'))   \
        ret = 1;    \
        ret;    \
})

static void 
stripstring(char* str)
{
    if (str == NULL){
        return;
    }

    int len = strlen(str);
    while(len > 0 && !VALID_CHAR(*(str + (--len)))) *(str + len) = '\0';
    if (len > 0)
    while(!VALID_CHAR(*str))  ++str;
}

void 
tc_setting_value(char* key ,char* value,config_setting* config)
{
    int i = 0;
    int n;
    if (key == NULL || value == NULL){
        return;
    }
    
    if (*key == '\0' || *value == '\0'){
        fprintf(stderr,"%s: value is empty\n",__FUNCTION__);
        return;
    }

    for (;config[i].str != NULL;++i)
    {
        if (strcmp(key ,config[i].str) == 0)
        {
            switch(config[i].type)
            {
                case TYPE_CHAR_PTR:
                {
                    if (*(char**)(config[i].value_ptr_to_ptr) != NULL){
                        break;
                    }
                    n = strlen(value) + 1;
                    if ((*(char**)(config[i].value_ptr_to_ptr) = (char*)malloc(sizeof(char)*n)) == NULL){
                        fprintf(stderr,"%s: malloc failed \n",__FUNCTION__);
                        break;
                    }
                    snprintf(*(char**)(config[i].value_ptr_to_ptr) ,n ,"%s",value);
                    
                    break;
                }
                case TYPE_UNSIGNED_INT:
                {
                     if (config[i].limit > 0 && config[i].shift >= 0)
                    {
                         int tmp = atoi(value);
                        unsigned int* val = (unsigned int*)(config[i].value_pointer);
                         int limit = (int)config[i].limit;
                         int shift = (int)config[i].shift;
                        *val = (*val & (~limit)) | (limit & (tmp << shift));
                    } else {
                        *(unsigned int *)(config[i].value_pointer) = atoi(value);
                    }
                    break;
                }
                case TYPE_LONG:
                {
                     if (config[i].limit > 0 && config[i].shift >= 0)
                    {
                         long tmp = atol(value);
                         long* val = (long*)(config[i].value_pointer);
                         long limit = (long)config[i].limit;
                         long shift = (long)config[i].shift;
                        *val = (*val & (~limit)) | (limit & (tmp << shift));
                    } else {
                        *(long *)(config[i].value_pointer) = atol(value);
                    }
                    break;
                }
                case TYPE_SIZE_T:
                {
                     if (config[i].limit > 0 && config[i].shift >= 0)
                    {
                         size_t tmp = (size_t)atol(value);
                         size_t* val = (size_t*)(config[i].value_pointer);
                         size_t limit = (size_t)config[i].limit;
                         size_t shift = (size_t)config[i].shift;
                        *val = (*val & (~limit)) | (limit & (tmp << shift));
                    } else {
                        *(size_t *)(config[i].value_pointer) = (size_t)atol(value);
                    }
                    break;
                }
                case TYPE_UINT16_T:
                {
                     if (config[i].limit > 0 && config[i].shift >= 0)
                    {
                         uint16_t tmp = (uint16_t)atoi(value);
                         uint16_t* val = (uint16_t*)(config[i].value_pointer);
                         uint16_t limit = (uint16_t)config[i].limit;
                         uint16_t shift = (uint16_t)config[i].shift;
                        *val = (*val & (~limit)) | (limit & (tmp << shift));
                    } else {
                        *(uint16_t *)(config[i].value_pointer) = (uint16_t)atoi(value);
                    }
                    break;
                }
                case TYPE_CHAR_ARRAY:
                {
                    snprintf((char*)(config[i].value_pointer) ,config[i].limit, "%s" ,value);
                    break;
                }
                case TYPE_UINT8_T:
                {
                    if (config[i].limit > 0 && config[i].shift >= 0)
                    {
                         uint8_t tmp = (uint8_t)atoi(value);
                         uint8_t* val = (uint8_t*)(config[i].value_pointer);
                         uint8_t limit = (uint8_t)config[i].limit;
                         uint8_t shift = (uint8_t)config[i].shift;
                        *val = (*val & (~limit)) | (limit & (tmp << shift));
                    } else {
                        *(uint8_t*)(config[i].value_pointer) = (uint8_t)atoi(value);
                    }
                    
                    break;
                }
                case TYPE_IPV4_ADDR:
                {
                    if (is_valid_ipv4_addr(value)){
                        *(unsigned int *)(config[i].value_pointer) = inet_addr(value);
                    } else {
                        fprintf(stderr,"%s: %s = %s is not valid address \n",__FUNCTION__,key,value);
                    }
                    break;
                }
                default:
                fprintf(stderr,"%s: no such config item :%s\n",__FUNCTION__,config[i].str);
                break;
            }
        }
    }
    
}

int 
tc_setting_from_conf(config_setting* config,char* config_file)
{
    FILE* pf = NULL;
    char buffer[BUFFER_LEN] = {0};
    char *bp = NULL;
    char* vptr = NULL;

    if (config == NULL || config_file == NULL){
     fprintf(stderr,"%s: arg NULL ",__FUNCTION__);
     return -1;
    }
    if ((pf = fopen(config_file,"r")) == NULL){
        fprintf(stderr,"%s: read config file error :%s",__FUNCTION__,strerror(errno));
        return -1;
    }

    while(fgets(buffer,BUFFER_LEN,pf) != NULL)
    {
        bp = buffer;
        stripstring(bp);
        if (*bp == '#'){
            continue;
        }
        if ((vptr = strchr(bp,'=')) == NULL){
            continue;
        }
        stripstring(vptr);
        stripstring(bp);

        tc_setting_value(bp,vptr,config);
    }

    fclose(pf);
    return 0;
    
}



static unsigned short buf[32768]; 

unsigned short
tcpcsum(unsigned char *iphdr, unsigned short *packet, int pack_len)
{       
    unsigned short        res;

    memcpy(buf, iphdr + 12, 8); 
    *(buf + 4) = htons((unsigned short)(*(iphdr + 9)));
    *(buf + 5) = htons((unsigned short)pack_len);
    memcpy(buf + 6, packet, pack_len);
    res = csum(buf, pack_len + 12);

    return res; 
}  
extern char **environ;
int tc_system(char *command) 
{
    int pid = 0, status = 0;

    if ( command == NULL )
        return 1;

    pid = fork();
    if ( pid == -1 )
        return -1;

    if ( pid == 0 ) {
        char *argv[4];
        argv[0] = "sh";
        argv[1] = "-c";
        argv[2] = command;
        argv[3] = 0;

        execve("/bin/sh", argv, environ);
        exit(127);
    }

    /* wait for child process return */
    do {
       if ( waitpid(pid, &status, 0) == -1 ) {
            if (errno != EINTR)
                return -1;
       }else{
            return status;
        }    
    } while (1);

    return status;
}

