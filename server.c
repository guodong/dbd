#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>

#include "comm.h"

#define PORT	9500
#define BACKLOG	100

//#define TUPLE_SIZE	512

int file;

typedef struct {
    int domain;
    int id;
    char *data;
} tuple;

char *get_tuple(int domain, int id)
{

}

void set_tuple(tuple *tuple)
{

}

void set_data(char *data, unsigned long addr, unsigned long size)
{
    lseek(file, addr, SEEK_SET);
    if(write(file, data, size)<0){
        perror("write data");
        exit(0);
    }
}

void get_data(char *buf, unsigned long addr, unsigned long size)
{
    lseek(file, addr, SEEK_SET);
    int i;
    i = read(file, buf, size);
    if(i<0) {
        perror("read data");
    }
}

static inline void readit(int f, void *buf, size_t len)
{
    ssize_t res;
    while (len > 0) {
        //DEBUG("*");
        if ((res = read(f, buf, len)) <= 0) {
            //if(errno != EAGAIN) {
            //err("Read failed: %m");
            //}
        } else {
            len -= res;
            buf += res;
        }
    }
}

static inline void writeit(int f, void *buf, size_t len)
{
    ssize_t res;
    while (len > 0) {
        //DEBUG("+");
        if ((res = write(f, buf, len)) <= 0){
            //err("Send failed: %m");
        }
        len -= res;
        buf += res;
    }
}

int main(int argc, char *argv[])
{
    int server_sockfd, client_sockfd, portno;
    int server_len, client_len;
    struct sockaddr_in server_address;
    struct sockaddr_in client_address;
    int result;
    fd_set readfds, testfds;
    portno = 8888;//atoi(argv[1]);

    server_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    server_address.sin_port = htons(portno);
    server_len = sizeof(server_address);

    if(-1==bind(server_sockfd, (struct sockaddr*)&server_address, server_len)) {
        perror("bind");
        return -1;
    }

    listen(server_sockfd, BACKLOG);

    FD_ZERO(&readfds);
    FD_SET(server_sockfd, &readfds);

    while(1) {
        char ch, rmt[9];
        int fd, nread;
        testfds = readfds;
        printf("server waiting\n");
        result = select(FD_SETSIZE, &testfds, (fd_set *)0, (fd_set *)0, (struct timeval *)0);
        if(result < 1) {
            perror("server full");
            exit(1);
        }

        for(fd = 0; fd < FD_SETSIZE; fd++) {
            if(FD_ISSET(fd, &testfds)) {
                if(fd == server_sockfd) {
                    client_len = sizeof(client_address);
                    client_sockfd = accept(server_sockfd, (struct sockaddr *)&client_address, &client_len);
                    FD_SET(client_sockfd, &readfds);
                    printf("adding client on fd %d\n", client_sockfd);
                    file = open("/root/dbd/test.img", O_RDWR);
                } else {
                    ioctl(fd, FIONREAD, &nread);

                    if(nread == 0) {
                        close(file);
                        FD_CLR(fd, &readfds);
                        printf("removing client on fd %d\n", fd);
                        close(fd);
                    } else {
                        struct dbd_request gw_req;
                        struct dbd_response gw_rep;
                        memset(&gw_req, 0, sizeof(gw_req));
                        int i;
                        printf("begin recv \n");
                        readit(fd, &gw_req, sizeof(gw_req));
                        printf("get data %ld %ld\n", gw_req.addr, gw_req.size);
                        memcpy(gw_rep.handle, gw_req.handle, 8);
                        gw_rep.addr = gw_req.addr;
                        gw_rep.size = gw_req.size;
                        //write(fd, &gw_rep, sizeof(gw_rep));
                        if(gw_req.dbd_cmd == DBD_CMD_READ){
                            char buf[gw_req.size];
                            get_data(buf, gw_req.addr, gw_req.size);
                            gw_rep.dbd_cmd = DBD_CMD_READ;
                            writeit(fd, &gw_rep, sizeof(gw_rep));
                            writeit(fd, buf, gw_req.size);
                            printf("send data\n");
                        }else{
                            gw_rep.dbd_cmd = DBD_CMD_WRITE;
                            printf("write data\n");
                            char bf[gw_req.size];
                            readit(fd, bf, gw_req.size);
                            set_data(bf, gw_req.addr, gw_req.size);
                            writeit(fd, &gw_rep, sizeof(gw_rep));
                        }
//                        i = read(fd, &gw_req.seq, 4);
//                        printf("get seq %d bytes %d\n", i, gw_req.seq);
//                        if(i<4)printf("not complete\n\n");
//                        i = read(fd, &gw_req.length, 4);
//                        printf("get length %d bytes %d\n", i, gw_req.length);
//                        if(i<4)printf("not complete\n\n");
//                        i = read(fd, &gw_req.dbd_cmd, 4);
//                        printf("get cmd %d bytes %d\n", i, gw_req.dbd_cmd);
//                        if(i<4)printf("not complete\n\n");
//                        i = read(fd, &gw_req.tuple_id, 8);
//                        printf("get tuple_id %d bytes %d\n", i, gw_req.tuple_id);
//                        if(i<8)printf("not complete\n\n");

                        //write(fd, "b", 1);

                    }
                }
            }
        }
    }
    return 0;
}
