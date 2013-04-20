
#include <linux/wait.h>
#include <linux/types.h>
#include "list.h"
#define TUPLE_SIZE (64*1024)
#define UNIT_SIZE (1024*1024*4)

enum dbd_cmd {
    DBD_CMD_IO_READ,
    DBD_CMD_IO_WRITE
};

struct dbd_request {
    int domain;
    enum dbd_cmd cmd;
    char handle[8];
    unsigned long addr;
    unsigned long size;
} __attribute__ ((packed));

struct dbd_response {
    char handle[8];
} __attribute__ ((packed));

struct server {
    int id;
    unsigned int mask;
    char is_back;
    int ip;
    int port;
    struct list_head list_node;
    struct task_struct *send_thread;
    struct task_struct *recv_thread;
    struct list_head sending_list; /* Requests waiting result */
    struct list_head waiting_list; /* Requests to be sent */
    wait_queue_head_t send_wq;
    wait_queue_head_t recv_wq;
    struct socket *sock;
};

struct farm {
    struct list_head server_list;
};

struct dbd_request_wrapper{
    struct list_head list_node;
    struct request *request;
    char *buf;
};

struct dbd_request_wrapper_item{
    struct list_head list_node;
    struct server *server;
    unsigned long addr;
    unsigned long size;
};
