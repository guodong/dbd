#ifndef DBD_H_INCLUDED
#define DBD_H_INCLUDED

#include "defs.h"
#define NETLINK_PROTOCAL    24

struct dbd_device {
    char name[DBD_NAME_SIZE];
    int major;
    struct gendisk *disk;
    spinlock_t queue_lock;
    spinlock_t lock;
    struct list_head list_node;
    wait_queue_head_t waiting_wq;
    struct task_struct *thread;
    struct list_head bio_list;
    struct request_queue *queue;
    char exit;
};

struct dbd_io_request {
    enum dbd_msg_type type;
    char name[DBD_NAME_SIZE];
    uint64_t addr;
    uint32_t size;
    char handle[8];
} __attribute__((packed));

struct dbd_io_response {
    int result;
    char handle[8];
} __attribute__((packed));

struct dbd_meta {
    char name[DBD_NAME_SIZE];
    uint64_t size;
} __attribute__((packed));

struct dbd_server {
    char ip[16];
    int port;
    uint64_t seq;
    uint64_t mask;
    struct list_head list_node;
    struct socket *sock;
    struct task_struct *recv_thread;
    wait_queue_head_t waiting_wq;
    int ref; //the requests number runing on this server
    int exit;
};
/*
enum dbd_nlmsg_type {
    DBD_NLMSG_CREATE,
    DBD_NLMSG_READ,
    DBD_NLMSG_WRITE,
};

struct dbd_nlmsg_request {
    enum dbd_cmd type;
    char name[DBD_NAME_SIZE];
    uint64_t addr;
    uint32_t size;
    char handle[8];
} __attribute__((packed));

struct dbd_nlmsg_response {
    char handle[8];
} __attribute__((packed));

struct dbd_nlmsghdr {
    enum dbd_cmd type;
    unsigned int size;
} __attribute__((packed));
*/
#define DBD_MSG_HDRLEN	 ((int) (sizeof(struct dbd_msghdr)))
#define DBD_MSG_LENGTH(len) ((len)+(DBD_MSG_HDRLEN))
#define DBD_MSG_SPACE(len) (DBD_MSG_LENGTH(len))
#define DBD_MSG_DATA(nlh)  ((void*)(((char*)nlh) + DBD_MSG_LENGTH(0)))

#endif // DBD_H_INCLUDED
