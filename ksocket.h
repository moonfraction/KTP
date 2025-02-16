/*=====================================
Assignment 4 Submission
Name: Chandransh Singh
Roll number: 22CS30017
=====================================*/


#ifndef KSOCKET_H
#define KSOCKET_H

#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#define SOCK_KTP SOCK_DGRAM
#define ENOSPACE 1111
#define ENOTBOUND 1112
#define ENOMESSAGE 1113
#define MAX_DATA_SIZE 512 // Maximum data size
#define HEADER_SIZE 8
#define PKT_SIZE (MAX_DATA_SIZE + HEADER_SIZE)
#define BUF_SIZE MAX_DATA_SIZE

#define T 5
#define p 0.1
#define N 10

#define DATA_MSG 0
#define ACK_MSG 1

typedef struct ktp_socket{
    int sockfd;
    struct sockaddr_in src;
    struct sockaddr_in dest;
    int bound;
    int next_seqno;
    int last_ackno;
    int exp_seqno;
} ktp_socket;

// function prototypes
int k_socket(int domain, int type, int protocol);
int k_bind(int sockfd, const struct sockaddr *src_addr, socklen_t addrlen, const struct sockaddr *dest_addr, socklen_t dest_len);
ssize_t k_sendto(int sockfd, const void *buf, size_t len, int flags, struct sockaddr *dest_addr, socklen_t addrlen);
ssize_t k_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
int k_close(int sockfd);

int dropMessage(float prob);

#endif