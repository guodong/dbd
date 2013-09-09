
#ifndef DEFS_H
#define DEFS_H

#define DBD_NAME_SIZE  64

//enum dbd_cmd {
//    DBD_CMD_IO_READ,
//    DBD_CMD_IO_WRITE,
//    DBD_CMD_CTRL_CREATE,
//    DBD_CMD_CTRL_REMOVE,
//    DBD_CMD_CTRL_UPDATE,
//    DBD_CMD_RESPONSE_OSCREATE,
//    DBD_CMD_CHECK_DISK_STATUS,
//};

enum dbd_msg_type{
    DBD_MSG_CREATE,
    DBD_MSG_READ,
    DBD_MSG_WRITE,
    DBD_MSG_RESPONSE,
    DBD_MSG_RESPONSE_OSCREATE,
    DBD_MSG_CREATEOS,
};

struct dbd_msghdr{
    enum dbd_msg_type type;
    unsigned int size;
} __attribute__((packed));

struct dbd_msg{
    struct dbd_msghdr head;
    char *body;
} __attribute__((packed));

struct io_request {
    uint16_t version;
    uint64_t unit_id;
    int offset;
    int size;
    int inner_offset;
    enum dbd_msg_type type;
    struct dbd_server *server;
    struct list_head list_node;
    char handle[8];
} __attribute__((packed));

struct io_response {
    char handle[8];
    int inner_offset;
    int size;
} __attribute__((packed));


#endif
