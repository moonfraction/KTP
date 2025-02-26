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

ktp_socket ktp_sockets[N];
int sock_count = 0;

int dropMessage(float prob){
    float r = (float)rand() / (float)RAND_MAX;
    return r < prob;
}

int k_socket(int domain, int type, int protocol){
    if(domain != AF_INET || type != SOCK_KTP || protocol != 0){
        errno = EINVAL;
        return -1;
    }
    if(sock_count >= N){
        errno = ENOSPACE;
        return -1;
    }

    int sockfd = socket(domain, type, protocol);
    if(sockfd == -1){
        perror("Error creating socket\n");
        return -1;
    }
    printf("Socket created\n");

    ktp_socket sock;
    sock.sockfd = sockfd;
    sock.bound = 0;
    sock.next_seqno = 1;    
    sock.last_ackno = 0;
    sock.exp_seqno = 1;
    ktp_sockets[sock_count] = sock;
    sock_count++;

    return sockfd;
}

ktp_socket* find_sock(int sockfd){
    ktp_socket *sock = NULL;
    int i;
    for(i = 0; i < sock_count; i++){
        if(ktp_sockets[i].sockfd == sockfd){
            sock = &ktp_sockets[i];
            break;
        }
    }
    if(sock == NULL || i == sock_count){
        errno = ENOTSOCK;
        return NULL;
    }
    return sock;
}

int k_bind(int sockfd, const struct sockaddr *src_addr, socklen_t addrlen, const struct sockaddr *dest_addr, socklen_t dest_len){
    if(src_addr == NULL || dest_addr == NULL){
        errno = EINVAL;
        return -1;
    }

    struct sockaddr_in *src = (struct sockaddr_in *)src_addr;
    struct sockaddr_in *dest = (struct sockaddr_in *)dest_addr;

    if(src->sin_family != AF_INET || dest->sin_family != AF_INET){
        errno = EINVAL;
        return -1;
    }

    ktp_socket *sock = find_sock(sockfd);
    if(sock == NULL){
        perror("Error finding socket\n");
        return -1;
    }

    sock->src = *src;
    sock->dest = *dest;

    if(bind(sockfd, src_addr, addrlen) == -1){
        perror("Error binding socket\n");
        return -1;
    }
    printf("Socket bound\n");
    
    sock->bound = 1;

    return 0;
}


ssize_t k_sendto(int sockfd, const void *buf, size_t len, int flags, struct sockaddr *dest_addr, socklen_t addrlen){
    if(buf == NULL || dest_addr == NULL){
        errno = EINVAL;
        return -1;
    }

    ktp_socket *sock = find_sock(sockfd);
    if(sock == NULL){
        perror("Error finding socket\n");
        return -1;
    }

    if(!sock->bound){
        errno = ENOTBOUND;
        return -1;
    }

    if(len == 0){
        return 0;
    }


    char *pkt = (char *)malloc(PKT_SIZE);
    if(pkt == NULL){
        perror("Error allocating memory\n");
        return -1;
    }

    pkt[0] = sock->next_seqno;
    pkt[1] = DATA_MSG;

    size_t data_len = len > MAX_DATA_SIZE ? MAX_DATA_SIZE : len;
    memcpy(pkt + HEADER_SIZE, buf, data_len);

    struct timeval tv;
    tv.tv_sec = T;
    tv.tv_usec = 0;

    fd_set readfds;
    int maxfd = sockfd + 1;
    FD_ZERO(&readfds);

    while(1){
        if(sendto(sock->sockfd, pkt, data_len + HEADER_SIZE, flags, dest_addr, addrlen) == -1){
            perror("Error sending packet\n");
            return -1;
        }
        // printf("Packet sent with seqno %d\n", sock->next_seqno);

        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);
        int ret = select(maxfd, &readfds, NULL, NULL, &tv);
        // printf("ret = %d\n", ret);
        if(ret == -1){
            perror("Error in select\n");
            return -1;
        }
        else if(ret == 0){
            // tv.tv_sec = T;
            // tv.tv_usec = 0;
            continue;
        }
        else{
            char ack_pkt[HEADER_SIZE];
            // printf("sock->next_seqno = %d\n", sock->next_seqno);
            if(recvfrom(sock->sockfd, ack_pkt, HEADER_SIZE, flags, dest_addr, &addrlen) == -1){
                perror("Error receiving ack\n");
                return -1;
            }
            // printf("ack_pkt[0] = %d\n", ack_pkt[0]);

            if(dropMessage(p)){
                printf("Ack dropped with seqno %d\n", sock->next_seqno);
                continue;
            }

            if(ack_pkt[0] == sock->next_seqno && ack_pkt[1] == ACK_MSG){
                sock->last_ackno = sock->next_seqno;
                sock->next_seqno++;
                break;
            }
        }
        // if ack is not received, resend the packet after timeout
    }

    free(pkt);
    return data_len;
}

ssize_t k_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen){
    if(buf == NULL || src_addr == NULL){
        errno = EINVAL;
        return -1;
    }

    ktp_socket *sock = find_sock(sockfd);
    if(sock == NULL){
        perror("Error finding socket\n");
        return -1;
    }

    if(!sock->bound){
        errno = ENOTBOUND;
        return -1;
    }

    if(len == 0){
        return 0;
    }

    char *pkt = (char *)malloc(PKT_SIZE);
    if(pkt == NULL){
        perror("Error allocating memory\n");
        return -1;
    }

    struct timeval tv;
    tv.tv_sec = T;
    tv.tv_usec = 0;

    fd_set readfds;
    int maxfd = sockfd + 1;
    FD_ZERO(&readfds);

    int recvlen;

    while(1){
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);
        int ret = select(maxfd, &readfds, NULL, NULL, &tv);
        if(ret == -1){
            perror("Error in select\n");
            return -1;
        }
        else if(ret == 0){
            tv.tv_sec = T;
            tv.tv_usec = 0;
            continue;
        }
        else{
            if((recvlen = recvfrom(sock->sockfd, pkt, PKT_SIZE, flags, src_addr, addrlen)) == -1){
                perror("Error receiving packet\n");
                return -1;
            }

            if(dropMessage(p)){
                printf("Packet dropped with seqno %d\n", pkt[0]);
                continue;
            }
            
            char ack_pkt[HEADER_SIZE];
            ack_pkt[0] = pkt[0];
            ack_pkt[1] = ACK_MSG;
            if(sendto(sock->sockfd, ack_pkt, HEADER_SIZE, flags, src_addr, *addrlen) == -1){
                perror("Error sending ack\n");
                return -1;
            }
            if(pkt[0] == sock->exp_seqno && pkt[1] == DATA_MSG){
                memcpy(buf, pkt + HEADER_SIZE, recvlen - HEADER_SIZE);
                sock->exp_seqno++;
                // printf("sock->exp_seqno = %d\n", sock->exp_seqno);
                break;
            }
        }
        // if packet is not received, resend the ack after timeout
    }

    free(pkt);
    return recvlen - HEADER_SIZE;
}

int k_close(int sockfd){
    ktp_socket *sock = find_sock(sockfd);
    if(sock == NULL){
        perror("Error finding socket\n");
        return -1;
    }

    if(close(sockfd) == -1){
        perror("Error closing socket\n");
        return -1;
    }

    int i;
    for(i = 0; i < sock_count; i++){
        if(ktp_sockets[i].sockfd == sockfd){
            break;
        }
    }

    for(; i < sock_count - 1; i++){
        ktp_sockets[i] = ktp_sockets[i + 1];
    }
    sock_count--;

    return 0;
}