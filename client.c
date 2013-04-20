#include <sys/stat.h>   
#include <unistd.h>   
#include <stdio.h>   
#include <stdlib.h>   
#include <sys/socket.h>   
#include <sys/types.h>   
#include <string.h>   
#include <asm/types.h>   
#include <linux/netlink.h>   
#include <linux/socket.h>   
#include <errno.h>
#include <pthread.h>
#include <asm-generic/errno-base.h>

#include "defs.h"
#include "ucomm.h"
#include "list.h"
#include "cs.h"
#include "old/btree.h"

#define MAX_PAYLOAD 1024  // maximum payload size   

static int sock_fd;
static struct list_head local_request_list;
static struct list_head remote_request_wrapper_list;

char bf[1024*1024*16];

void nl_send(void *buf, int length, int flags) {
    struct sockaddr_nl addr;
    struct nlmsghdr *nlh, *base;
    struct msghdr msg;
    struct iovec iov;
    int result, len;

    addr.nl_family = AF_NETLINK;
    addr.nl_pid = 0;
    addr.nl_groups = 1;

    len = NLMSG_SPACE(length);

    nlh = base = (struct nlmsghdr*) malloc(len);
    memset(nlh, 0, len);
    nlh->nlmsg_len = len;
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;
    memcpy(NLMSG_DATA(nlh), buf, length);

    do {
        iov.iov_base = base;
        iov.iov_len = len;

        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        //result = sendmsg(sock_fd, &msg, MSG_WAITALL);
        result = sendto(sock_fd, base, len, flags, (struct sockaddr*) &addr, sizeof (addr));
        printf("rt: %d %s", result, strerror(errno));
        len -= result;
        base += result;
    } while (len > 0);
    //sendto(sock_fd, nlh, nlh->nlmsg_len, 0, (struct sockaddr*) &addr, sizeof (addr));
    free(nlh);
}

int nl_recv(void *buf, int length) {
    struct sockaddr_nl dest_addr;
    struct msghdr msg;
    struct iovec iov;
    struct nlmsghdr *nlh, *base;
    char mg[10];
    int result;
    int len = NLMSG_SPACE(length);
    dbd_log("start recv");
    memset(&dest_addr, 0, sizeof (dest_addr));

    nlh = base = (struct nlmsghdr*) malloc(len);
    do {
        iov.iov_base = base;
        iov.iov_len = len;

        msg.msg_name = (void *) &dest_addr;
        msg.msg_namelen = sizeof (dest_addr);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        result = recvmsg(sock_fd, &msg, MSG_WAITALL);
        sprintf(mg, "recv %d bytes", result);
        dbd_log(mg);
        if (result < 0) {
            char e[100];
            sprintf(e, "%s", strerror(errno));
            dbd_log(e);
            break;
        }
        len -= result;
        base += result;
    } while (len > 0);
    memcpy(buf, NLMSG_DATA(nlh), length);
    free(nlh);
    return 1;
}

static struct dbd_remote_request_wrapper *find_request_wrapper(struct dbd_remote_request_wrapper *xwrapper) {
    struct dbd_remote_request_wrapper *wrapper, *tmp;

    list_for_each_entry_safe(wrapper, tmp, &remote_request_wrapper_list, list_node) {
        if (wrapper != xwrapper) {
            continue;
        }
        return wrapper;
    }
    return (void*) (-ENOENT);
}

void *remote_recv_thread(void *data) {
    struct dbd_remote_response rsps;
    while (1) {
        dbd_gateway_recv(&rsps, sizeof (rsps), 0);
        struct dbd_remote_request_wrapper *wrapper = find_request_wrapper(*(struct dbd_remote_request_wrapper **) rsps.handle);

        //here receive readed data
        switch (wrapper->local_request->cmd) {
            case DBD_CMD_IO_READ:
                dbd_gateway_recv(wrapper->buf, wrapper->local_request->size, 0);
                break;
            default:
                break;
        }

        wrapper->count--;
        if (wrapper->count == 0) {
            // io complete, send msg to kernel
            struct dbd_local_msg msg;
            msg.type = DBD_LOCAL_MSG_RESPONSE;
            memcpy(msg.response.handle, wrapper->local_request->handle, 8);
            //int flags = wrapper->local_request->cmd == DBD_CMD_IO_READ ? MSG_MORE : 0;
            //nl_send(&msg, sizeof (msg), flags);
            if (wrapper->local_request->cmd == DBD_CMD_IO_READ) {
                char *s_buf = malloc(sizeof (msg) + wrapper->local_request->size);
                memcpy(s_buf, &msg, sizeof (msg));
                memcpy(s_buf + sizeof (msg), wrapper->buf, wrapper->local_request->size);
                
                //memcpy(s_buf + sizeof (msg), &bf[wrapper->local_request->addr], wrapper->local_request->size);
                
                nl_send(s_buf, sizeof (msg) + wrapper->local_request->size, 0);
                free(s_buf);
            } else {
                nl_send(&msg, sizeof (msg), 0);
            }
            free(wrapper->local_request);
            free(wrapper->buf);
            list_del_init(&wrapper->list_node);
            free(wrapper);
        }
    }
}

void *local_recv_thread(void *data) {
    while (1) {
        struct dbd_local_request *rqst = malloc(sizeof (struct dbd_local_request));
        nl_recv(rqst, sizeof (*rqst));
        char msg[100];
        sprintf(msg, "cmd:%d addr: %ld size: %ld", rqst->cmd, rqst->addr, rqst->size);
        dbd_log(msg);
        struct dbd_remote_request_wrapper *wrapper = malloc(sizeof (struct dbd_remote_request_wrapper));
        INIT_LIST_HEAD(&wrapper->remote_request_list);
        list_add(&wrapper->list_node, &remote_request_wrapper_list);
        wrapper->local_request = rqst;
        wrapper->count = 1;
        wrapper->buf = malloc(rqst->size);

        struct dbd_remote_request *remote_rqst = malloc(sizeof (struct dbd_remote_request));

        remote_rqst->addr = rqst->addr;
        remote_rqst->cmd = rqst->cmd;
        remote_rqst->size = rqst->size;
        memcpy(remote_rqst->handle, &wrapper, sizeof (wrapper));
        dbd_gateway_send(remote_rqst, sizeof (*remote_rqst), 0);
        if (rqst->cmd == DBD_CMD_IO_WRITE) {
            nl_recv(wrapper->buf, rqst->size);
            dbd_gateway_send(wrapper->buf, rqst->size, 0);
            //memcpy(bf + rqst->addr, wrapper->buf, rqst->size);
        }


        // free remote_rqst after receive all response, see remote_recv_thread
    }
}

int main(int argc, char* argv[]) {
    struct sockaddr_nl src_addr;
    int retval;

    INIT_LIST_HEAD(&remote_request_wrapper_list);
    sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_PROTOCAL);
    if (sock_fd == -1) {
        printf("error getting socket: %s", strerror(errno));
        return -1;
    }

    // To prepare binding   
    memset(&src_addr, 0, sizeof (src_addr));
    src_addr.nl_family = PF_NETLINK;
    src_addr.nl_pid = getpid(); // self pid    
    src_addr.nl_groups = 1; // multi cast   

    retval = bind(sock_fd, (struct sockaddr*) &src_addr, sizeof (src_addr));
    if (retval < 0) {
        printf("bind failed: %s", strerror(errno));
        close(sock_fd);
        return -1;
    }

    pthread_t thread;
    if (pthread_create(&thread, NULL, local_recv_thread, NULL)) {
        goto out;
    }
    pthread_t thread1;
    if (pthread_create(&thread1, NULL, remote_recv_thread, NULL)) {
        goto out;
    }

    struct dbd_local_msg msg;
    memset(&msg, 0, sizeof (msg));
    msg.type = DBD_LOCAL_MSG_REQUEST;
    msg.request.cmd = DBD_CMD_CTRL_CREATE;

    nl_send(&msg, sizeof (msg), 0);
    printf("send type: %d", msg.type);
    fflush(stdout);
    getchar();
out:
    printf("out\n");
    close(sock_fd);

    return 0;
} 