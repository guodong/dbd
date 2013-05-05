/* 
 * File:   cs.h
 * Author: root
 *
 * Created on March 25, 2013, 2:33 AM
 */

#ifndef CS_H
#define	CS_H

#ifdef	__cplusplus
extern "C" {
#endif

#include "list.h"
#include "defs.h"

#define UNIT_SIZE (1024*1024)
    
    struct dbd_server{
        char ip[16];
        int port;
        int seq;
        int mask;
        struct list_head list_node;
        int sockfd;
        pthread_t thread;
    };

    struct dbd_remote_request {
        int domain;
        enum dbd_cmd cmd;
        char handle[8];
        unsigned long addr;
        int size;
        struct list_head list_node;
        int unit_id;
        int request_offset;
        struct dbd_server *server;
    } __attribute__((packed));

    struct dbd_remote_response {
        char handle[8];
        int unit_id;
        int request_offset;
    } __attribute__((packed));
    
    struct dbd_remote_request_wrapper{
        struct list_head remote_request_list;
        struct list_head list_node;
        struct dbd_local_request *local_request;
        int count;
        char *buf;      // used for io read
    };




#ifdef	__cplusplus
}
#endif

#endif	/* CS_H */

