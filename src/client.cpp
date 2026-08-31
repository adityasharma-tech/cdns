#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define PORT 5349
#define MAXLINE 1024

int main(int argc, char *argv[]){
    if(argc < 2){
        perror("please type the message u want to send");
        exit(EXIT_FAILURE);
    }

    int sockfd;
    const char *hello = argv[1];
    struct sockaddr_in servaddr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    if(sockfd < 0){
        perror("failed to create socket");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr.sin_port = htons(PORT);

    int n = sendto(sockfd, hello, strlen(hello), 0, (const struct sockaddr *)&servaddr, sizeof(servaddr));

    if(n < 0){
        perror("sendto failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    std::cout << "Hello message sent \n" << std::endl;

    close(sockfd);

    return 0;
}
