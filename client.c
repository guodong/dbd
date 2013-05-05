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

static int sock_fd;
static struct list_head local_request_list;
static struct list_head remote_request_wrapper_list;
static struct list_head server_list;

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
    struct dbd_server *server = data;
    struct dbd_remote_response rsps;
    while (1) {
        dbd_gateway_recv(server, &rsps, sizeof (rsps), 0);
        struct dbd_remote_request_wrapper *wrapper = find_request_wrapper(*(struct dbd_remote_request_wrapper **) rsps.handle);

        //here receive readed data
        switch (wrapper->local_request->cmd) {
            case DBD_CMD_IO_READ: // should be saved in unit cache, then read in cache.
                dbd_gateway_recv(server, &wrapper->buf[rsps.request_offset*UNIT_SIZE], UNIT_SIZE, 0);
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
                int offset = wrapper->local_request->addr % UNIT_SIZE;
                memcpy(s_buf + sizeof (msg), &wrapper->buf[offset], wrapper->local_request->size);


                nl_send(s_buf, sizeof (msg) + wrapper->local_request->size, 0);
                free(s_buf);
            } else {
                nl_send(&msg, sizeof (msg), 0);
            }
            struct dbd_remote_request *rqst, *tmp;

            list_for_each_entry_safe(rqst, tmp, &wrapper->remote_request_list, list_node) {
                list_del_init(&rqst->list_node);
                free(rqst);
            }
            free(wrapper->local_request);
            free(wrapper->buf);
            list_del_init(&wrapper->list_node);
            free(wrapper);
        }
    }
}

struct dbd_server *find_server(int unit_id) {
    struct dbd_server *serv, *tmp;

    list_for_each_entry_safe(serv, tmp, &server_list, list_node) {
        if ((unit_id & serv->mask) != serv->seq)
            continue;
        return serv;
    }
    return (void*) 0;
}

struct dbd_remote_request_wrapper *make_wrapper(struct dbd_local_request *rqst) {
    struct dbd_remote_request_wrapper *wrapper = malloc(sizeof (struct dbd_remote_request_wrapper));
    INIT_LIST_HEAD(&wrapper->remote_request_list);
    wrapper->local_request = rqst;

    int addr = rqst->addr;
    int size = rqst->size, count = 0, offset = 0, send_size = 0;

    int unit_id = addr / UNIT_SIZE;
    send_size = (rqst->size > (UNIT_SIZE - addr % UNIT_SIZE)) ? (UNIT_SIZE - addr % UNIT_SIZE) : rqst->size;
    while (size > 0) {

        struct dbd_server *server = find_server(unit_id);

        struct dbd_remote_request *remote_rqst = malloc(sizeof (struct dbd_remote_request));
        INIT_LIST_HEAD(&remote_rqst->list_node);

        list_add(&remote_rqst->list_node, &wrapper->remote_request_list);

        remote_rqst->server = server;
        remote_rqst->unit_id = unit_id++;
        remote_rqst->addr = (count == 0) ? (rqst->addr % UNIT_SIZE) : 0;
        remote_rqst->cmd = rqst->cmd;
        remote_rqst->size = send_size; //size > UNIT_SIZE ? UNIT_SIZE - remote_rqst->addr : size;
        remote_rqst->request_offset = offset;
        memcpy(remote_rqst->handle, &wrapper, sizeof (wrapper));

        size -= send_size;
        count++;
        offset += 1;
        send_size = size > UNIT_SIZE ? UNIT_SIZE : size;
    }

    wrapper->count = count;
    wrapper->buf = malloc(count * UNIT_SIZE);
    return wrapper;
}

void *local_recv_thread(void *data) {
    while (1) {
        struct dbd_local_request *rqst = malloc(sizeof (struct dbd_local_request));
        nl_recv(rqst, sizeof (*rqst));
        struct dbd_remote_request_wrapper *wrapper = make_wrapper(rqst); // make a remote request wrapper that contains many request to server
        list_add(&wrapper->list_node, &remote_request_wrapper_list);

        if (DBD_CMD_IO_WRITE == rqst->cmd) {
            int offset = rqst->addr % UNIT_SIZE;
            nl_recv(&wrapper->buf[offset], rqst->size);
        }

        struct dbd_remote_request *remote_rqst, *tmp;

        list_for_each_entry_safe(remote_rqst, tmp, &wrapper->remote_request_list, list_node) {
            dbd_gateway_send(remote_rqst->server, remote_rqst, sizeof (*remote_rqst), 0);
            if (DBD_CMD_IO_WRITE == rqst->cmd) {
                dbd_gateway_send(remote_rqst->server, &wrapper->buf[remote_rqst->request_offset * UNIT_SIZE], UNIT_SIZE, 0);
            }
        }

        // free remote_rqst after receive all response, see remote_recv_thread
    }
}

void init_server_list() {
    INIT_LIST_HEAD(&server_list);

    struct dbd_server *server, *s1 = malloc(sizeof (struct dbd_server));
    server = s1;
    memcpy(server->ip, "127.0.0.1", strlen("127.0.0.1"));
    server->port = 8888;
    server->seq = 0;
    server->mask = 0x1;
    server->sockfd = sock_connect(server);
    INIT_LIST_HEAD(&server->list_node);
    list_add(&server->list_node, &server_list);
    pthread_create(&server->thread, NULL, remote_recv_thread, server);

    struct dbd_server *s2 = malloc(sizeof (struct dbd_server));
    server = s2;
    memcpy(server->ip, "127.0.0.1", strlen("127.0.0.1"));
    server->port = 9999;
    server->seq = 1;
    server->mask = 0x1;
    server->sockfd = sock_connect(server);
    INIT_LIST_HEAD(&server->list_node);
    list_add(&server->list_node, &server_list);
    pthread_create(&server->thread, NULL, remote_recv_thread, server);
}

void remove_server_list() {
    struct dbd_server *server, *tmp;

    list_for_each_entry_safe(server, tmp, &server_list, list_node) {
        list_del(&server->list_node);
        close(server->sockfd);
        free(server);
    }
}

int main(int argc, char* argv[]) {
    struct sockaddr_nl src_addr;
    int retval;

    init_server_list();

    INIT_LIST_HEAD(&remote_request_wrapper_list);
    pthread_t thread;
    pthread_create(&thread, NULL, local_recv_thread, NULL);

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

    remove_server_list();

    return 0;
} 