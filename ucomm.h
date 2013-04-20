/* 
 * File:   dbd.h
 * Author: root
 *
 * Created on April 17, 2013, 1:15 PM
 */

#ifndef DBD_H
#define	DBD_H


#ifdef	__cplusplus
extern "C" {
#endif

#include "list.h"


#define NETLINK_PROTOCAL        24

    struct dbd_local_request {
        int domain;

        enum dbd_cmd cmd;
        char handle[8];
        unsigned long addr;
        int size;
        struct list_head list_node;
    } __attribute__((packed));

    struct dbd_local_response {
        int domain;
        enum dbd_cmd cmd;
        char handle[8];
        char uaddr[8];
    } __attribute__((packed));

    enum dbd_local_meg_type {
        DBD_LOCAL_MSG_REQUEST,
        DBD_LOCAL_MSG_RESPONSE
    };

    struct dbd_local_msg {
        enum dbd_local_meg_type type;

        union {
            struct dbd_local_request request;
            struct dbd_local_response response;
        };
    } __attribute__((packed));


#ifdef	__cplusplus
}
#endif

#endif	/* DBD_H */

