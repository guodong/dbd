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


#define TUPLE_SIZE (64*1024)
#define UNIT_SIZE (1024*1024*4)

    struct dbd_remote_request {
        int domain;
        enum dbd_cmd cmd;
        char handle[8];
        unsigned long addr;
        int size;
        struct list_head list_node;
    } __attribute__((packed));

    struct dbd_remote_response {
        char handle[8];
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

