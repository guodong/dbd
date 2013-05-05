#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>

#include "cs.h"

int sock_connect(struct dbd_server *server){
    int sockfd;
    struct sockaddr_in server_addr;
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket create");
        return -1;
    }
    bzero(&server_addr, sizeof (server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server->port);
    server_addr.sin_addr.s_addr = inet_addr(server->ip);

    if (connect(sockfd, (struct sockaddr*) &server_addr, sizeof (server_addr)) == -1) {
        perror("connect error");
        return -1;
    }
    return sockfd;
}

void dbd_gateway_send(struct dbd_server *server, void *buf, int length, int flags) {
    int sockfd = server->sockfd;
    int result;
    do {
        result = send(sockfd, buf, length, flags);
        length -= result;
        buf += result;
    }while(length>0);
}

void dbd_gateway_recv(struct dbd_server *server, void *buf, int length, int flags) {
    int sockfd = server->sockfd;
    int result;
    do {
        result = recv(sockfd, buf, length, flags);
        length -= result;
        buf += result;
    }while(length>0);
}





























