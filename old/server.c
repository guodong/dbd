#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include "uapi.h"

static void readit(int f, void *buf, size_t len) {
    int res;
    while (len > 0) {
        res = read(f, buf, len);
        len -= res;
        buf += res;

    }
}

static void writeit(int f, void *buf, size_t len) {
    int res;
    while (len > 0) {
        res = write(f, buf, len);
        len -= res;
        buf += res;
    }
}

int main(int argc, char *argv[]) {
    int port = atoi(argv[1]);
    char work_file[30];
    memset(work_file, '\0', 30);
    memcpy(work_file, argv[2], strlen(argv[2]));
    fd_set fds, fds_bk;
    int server_sockfd;
    struct sockaddr_in server_address;
    server_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    server_address.sin_port = htons(port);
    bind(server_sockfd, (struct sockaddr*) &server_address, sizeof (server_address));
    listen(server_sockfd, 10);

    FD_ZERO(&fds);
    FD_SET(server_sockfd, &fds);
    while (1) {
        int fd;
        fds_bk = fds;
        printf("server waiting\n");
        select(FD_SETSIZE, &fds_bk, (fd_set *) 0, (fd_set *) 0, (struct timeval *) 0);
        for (fd = 0; fd < FD_SETSIZE; fd++) {
            if (FD_ISSET(fd, &fds_bk)) {
                if (fd == server_sockfd) {
                    struct sockaddr_in client_address;
                    int client_len = sizeof (client_address);
                    int client_sockfd = accept(server_sockfd, (struct sockaddr *) &client_address, &client_len);
                    FD_SET(client_sockfd, &fds);
                    printf("adding client on fd %d\n", client_sockfd);
                } else {
                    int nread;
                    ioctl(fd, FIONREAD, &nread);
                    if (nread == 0) {
                        FD_CLR(fd, &fds);
                        printf("removing client on fd %d\n", fd);
                        close(fd);
                    } else {
                        struct dbd_request rqst;
                        struct dbd_response rsps;
                        
                        readit(fd, &rqst, sizeof(rqst));
                        printf("type: %d, addr: %d, size: %d", rqst.cmd, rqst.addr, rqst.size);
                        memcpy(rsps.handle, rqst.handle, 8);
                        if(rqst.cmd == DBD_CMD_IO_READ){
                            char now_work_file[30];
                            memset(now_work_file, '\0', 30);
                            char dm[10];
                            memset(dm, '\0', 30);
                            memcpy(now_work_file, work_file, 30);
                            sprintf(dm,"%d",rqst.domain);
                            strcat(now_work_file, dm);
                            printf("read file:%s\n", now_work_file);
                            char buf[rqst.size];
                            FILE *fp = fopen(now_work_file, "rb+");
                            fseek(fp, rqst.addr, SEEK_SET);
                            fread(buf, rqst.size, 1, fp);
                            fclose(fp);
                            writeit(fd, &rsps, sizeof(rsps));
                            writeit(fd, buf, rqst.size);
                        }else if(rqst.cmd == DBD_CMD_IO_WRITE){
                            char now_work_file[30];
                            memset(now_work_file, '\0', 30);
                            char dm[10];
                            memset(dm, '\0', 30);
                            memcpy(now_work_file, work_file, 30);
                            sprintf(dm,"%d",rqst.domain);
                            strcat(now_work_file, dm);
                            printf("write file:%s\n", now_work_file);
                            char buf[rqst.size];
                            readit(fd, buf, rqst.size);
                            FILE *fp = fopen(now_work_file, "rb+");
                            fseek(fp, rqst.addr, SEEK_SET);
                            fwrite(buf, rqst.size, 1, fp);
                            fclose(fp);
                            writeit(fd, &rsps, sizeof(rsps));
                        }
                    }
                }
            }
        }
    }

    return 0;
}

























