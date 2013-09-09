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



    enum dbd_manage_cmd {
        DBD_MANAGE_CMD_CREATE,
        DBD_MANAGE_CMD_REMOVE,
        DBD_MANAGE_CMD_OS_CREATE,
    };

	enum os_type{
		NONE,
		CENTOS_6_4_X86_64,
		WINDOWS_SERVER_2008_HPC,
	};

    struct dbd_server{
        char ip[16];
        int port;
        int seq;
        int mask;
        struct list_head list_node;
        int sockfd;
        pthread_t thread;
    };

    struct dbd_domain{
        uint64_t id;
        char name[DBD_NAME_SIZE];
        uint64_t size;
    } __attribute__((packed));

    struct dbd_remote_request {
        int domain_id;
        char name[50];
        enum dbd_msg_type type;
        enum os_type ostype;
        char handle[8];
        uint64_t addr;
        uint32_t size;
        uint64_t unit_id;
        int offset;
        struct dbd_server *server;
        struct list_head list_node;
    } __attribute__((packed));

    struct dbd_remote_response {
        enum dbd_msg_type type;
        char handle[8];
        uint64_t unit_id;
        int offset;
    } __attribute__((packed));

    struct dbd_remote_request_wrapper{
        struct list_head remote_request_list;
        //struct list_head list_node;
        struct dbd_io_request *local_request;
        int count;
        char *buf;      // used for io read
    };


#ifdef	__cplusplus
}
#endif

#endif	/* CS_H */

