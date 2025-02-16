/*=====================================
Assignment 4 Submission
Name: Chandransh Singh
Roll number: 22CS30017
=====================================*/


#include "ksocket.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/socket.h>
#include <time.h>

#define SND_PORT 8081
#define RCV_PORT 8080
#define INADDR "127.0.0.1"
#define INPUT_F "input.txt"

int main(){
    srand((unsigned int)time(NULL) * getpid());
    struct sockaddr_in src, dest;
    src.sin_family = AF_INET;
    src.sin_port = htons(SND_PORT);
    src.sin_addr.s_addr = inet_addr(INADDR);

    dest.sin_family = AF_INET;
    dest.sin_port = htons(RCV_PORT);
    dest.sin_addr.s_addr = inet_addr(INADDR);

    int sockfd = k_socket(AF_INET, SOCK_KTP, 0);
    if(sockfd == -1){
        perror("Error creating socket\n");
        return -1;
    }

    if(k_bind(sockfd, (struct sockaddr *)&src, sizeof(src), (struct sockaddr *)&dest, sizeof(dest)) == -1){
        perror("Error binding socket\n");
        return -1;
    }

    FILE *fp = fopen(INPUT_F, "r");
    if(fp == NULL){
        perror("Error opening file\n");
        exit(1);
    }

    char buf[BUF_SIZE];
    size_t len;
    int tot_transferred = 0;
    int tot_pkts = 0;
    while((len = fread(buf, 1, BUF_SIZE, fp)) > 0){
        ssize_t transferred = k_sendto(sockfd, buf, len, 0, (struct sockaddr *)&dest, sizeof(dest));
        if(transferred == -1){
            perror("Error sending packet\n");
            return -1;
        }
        tot_transferred += transferred;
        tot_pkts++;
        printf("pkt %d: %zd bytes transferred\n", tot_pkts, transferred);
    }

    // send EOF packet
    memset(buf, 0, BUF_SIZE);
    char eof_pkt[2] = "#";
    memcpy(buf, eof_pkt, 1);
    ssize_t transferred = k_sendto(sockfd, buf, 1, 0, (struct sockaddr *)&dest, sizeof(dest));
    if(transferred == -1){
        perror("Error sending packet EOF\n");
        return -1;
    }

    printf("Total transferred: %d bytes\n", tot_transferred);
    printf("Total packets: %d\n", tot_pkts);

    fclose(fp);
    k_close(sockfd);

    return 0;
}