/*=====================================
Assignment 4 Submission
Name: Chandransh Singh
Roll number: 22CS30017
=====================================*/

// steps to run the code
/*
make all
./user2  ## run this in one terminal -> receiver
./user1  ## run this in another terminal -> sender
*/


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

#define SND_PORT 8080
#define RCV_PORT 8081
#define INADDR "127.0.0.1"
#define OUTPUT_F "output.txt"

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

    FILE *fp = fopen(OUTPUT_F, "w");
    if(fp == NULL){
        perror("Error opening file\n");
        exit(1);
    }
    printf("waiting for data\n");

    char buf[BUF_SIZE];
    size_t len;
    int tot_received = 0;
    int tot_pkts = 0;

    while(1){
        socklen_t addrlen = sizeof(dest);
        len = k_recvfrom(sockfd, buf, BUF_SIZE, 0, (struct sockaddr *)&dest, &addrlen);
        if(len == -1){
            perror("Error receiving packet\n");
            return -1;
        }
        if(len == 0){
            break;
        }
        
        char *pkt = strstr(buf, "#");
        if(pkt != NULL){
            len = pkt - buf;
        }
        fwrite(buf, 1, len, fp);
        if(len) {
            tot_received += len;
            tot_pkts++;
            printf("pkt %d: %zu bytes received\n", tot_pkts, len);
        }
        if(pkt != NULL){
            break;
        }
    }

    printf("Total received: %d bytes\n", tot_received);
    printf("Total packets: %d\n", tot_pkts);

    fclose(fp);
    k_close(sockfd);

    return 0;

}