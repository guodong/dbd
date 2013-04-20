#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>

static int sockfd = 0;

void dbd_gateway_init() {
    struct sockaddr_in server_addr;
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket create");
        return;
    }
    bzero(&server_addr, sizeof (server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(8888);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(sockfd, (struct sockaddr*) &server_addr, sizeof (server_addr)) == -1) {
        perror("connect error");
        return;
    }
}

void dbd_gateway_send(void *buf, int length, int flags) {
    if (0 == sockfd) {
        dbd_gateway_init();
    }
    int result;
    do {
        result = send(sockfd, buf, length, flags);
        length -= result;
        buf += result;
    }while(length>0);
}

void dbd_gateway_recv(void *buf, int length, int flags) {
    if (0 == sockfd) {
        dbd_gateway_init();
    }
    int result;
    do {
        result = recv(sockfd, buf, length, flags);
        length -= result;
        buf += result;
    }while(length>0);
}





























