#include "ksocket.h"
#include <pthread.h>         // pthread_mutex_t
#include <stdlib.h>          // malloc
#include <sys/ipc.h>         // ftok
#include <sys/shm.h>         // shmget, shmat
#include <stdio.h>           // perror
#include <errno.h>           // errno
#include <unistd.h>          // getpid
#include <string.h>          // memset, memcpy
#include <arpa/inet.h>       // inet_pton
#include <sys/socket.h>      // socket
#include <netinet/in.h>      // sockaddr_in

static ktp_socket_t* ktp_sockets = NULL;
static pthread_mutex_t global_mutex = PTHREAD_MUTEX_INITIALIZER;

// Get the ktp_socket_t array from shared memory
ktp_socket_t* get_ktp_sockets(void) {
    // If already attached to shared memory in this process
    if (ktp_sockets != NULL) {
        return ktp_sockets;
    }
    
    pthread_mutex_lock(&global_mutex);
    
    // Double check after acquiring lock
    if (ktp_sockets != NULL) {
        pthread_mutex_unlock(&global_mutex);
        return ktp_sockets;
    }
    
    // Generate the same key that initksocket.c would use
    key_t key = ftok("/", 'A');
    if (key == -1) {
        perror("ftok failed in get_ktp_sockets");
        pthread_mutex_unlock(&global_mutex);
        return NULL;
    }
    
    // get the shared memory segment
    int shmid = shmget(key, sizeof(ktp_socket_t) * MAX_KTP_SOCK, 0666);
    if (shmid == -1) {
        perror("shmget failed in get_ktp_sockets");
        pthread_mutex_unlock(&global_mutex);
        return NULL;
    }
    
    // Attach to the shared memory segment
    ktp_sockets = (ktp_socket_t*)shmat(shmid, NULL, 0); // typecast to ktp_socket_t*
    if (ktp_sockets == (void*)-1) {
        perror("shmat failed in get_ktp_sockets");
        ktp_sockets = NULL;
        pthread_mutex_unlock(&global_mutex);
        return NULL;
    }
    
    pthread_mutex_unlock(&global_mutex);
    return ktp_sockets;
}

int k_socket(int domain, int type, int protocol){
    if(type != SOCK_KTP){
        errno = EINVAL;
        return -1;
    }

    // Get the ktp_socket_t array from shared memory
    ktp_socket_t* sock_arr = get_ktp_sockets();
    if (sock_arr == NULL) {
        return -1;
    }

    // lock the global mutex
    pthread_mutex_lock(&global_mutex);

    // find a free socket
    int sockfd;
    for(sockfd = 0; sockfd < MAX_KTP_SOCK; sockfd++){
        if(sock_arr[sockfd].is_alloc == 0 && sock_arr[sockfd].udp_sockfd >=0 ){
            break;
        }
    }

    // if no free socket found
    if(sockfd == MAX_KTP_SOCK){
        errno = ENOSPACE;
        pthread_mutex_unlock(&global_mutex);
        return -1;
    }

    /**** initialize the socket ****/
    // set the flag to indicate that socket is allocated
    sock_arr[sockfd].is_alloc = 1;
    // set the process id of the process that created the socket
    sock_arr[sockfd].pid = getpid();
    // set the udp socket file descriptor
    sock_arr[sockfd].udp_sockfd = socket(domain, SOCK_DGRAM, protocol);
    // set the flag to indicate that bind request is not made
    sock_arr[sockfd].bind_req = 0;
    // initialize the send window
    sock_arr[sockfd].swnd.size = WND_MAXSIZE;
    sock_arr[sockfd].swnd.base = 1;
    sock_arr[sockfd].swnd.next_seq_num = 1;
    sock_arr[sockfd].swnd.unack_cnt = 0;
    // initialize the receive window
    sock_arr[sockfd].rwnd.size = RECV_BUFSIZE;
    sock_arr[sockfd].rwnd.expected_seq_num = 1;
    sock_arr[sockfd].rwnd.last_ack_sent = 0;
    sock_arr[sockfd].rwnd.buffer_occupied = 0;
    sock_arr[sockfd].rwnd.buffer_read_pos = 0;
    sock_arr[sockfd].rwnd.buffer_write_pos = 0;
    sock_arr[sockfd].rwnd.nospace_flag = 0;
    // initialize the mutex - in initksocket.c

    // unlock the global mutex
    pthread_mutex_unlock(&global_mutex);

    printf("Process %d : [socket allocated : %d, udp_sockfd : %d]\n", getpid(), sockfd, sock_arr[sockfd].udp_sockfd);
    return sockfd;
}

int k_bind(int sockfd, const char* src_ip, int src_port, const char* dst_ip, int dst_port){    
    // Get the ktp_socket_t array from shared memory
    ktp_socket_t* sock_arr = get_ktp_sockets();
    if (sock_arr == NULL) {
        return -1;
    }

    // check the socket 
    if(sockfd < 0 || sockfd >= MAX_KTP_SOCK){
        errno = EBADF;
        return -1;
    }

    // check if the socket is allocated
    if(sock_arr[sockfd].is_alloc == 0){
        errno = EBADF;
        return -1;
    }


    // lock the socket mutex
    pthread_mutex_lock(&sock_arr[sockfd].mutex);

    // check src ip
    if(inet_pton(AF_INET, src_ip, &sock_arr[sockfd].src_addr.sin_addr) <= 0){
        errno = EINVAL;
        pthread_mutex_unlock(&sock_arr[sockfd].mutex);
        return -1;
    }

    // fill the source address
    memset(&sock_arr[sockfd].src_addr, 0, sizeof(struct sockaddr_in));
    sock_arr[sockfd].src_addr.sin_port = htons(src_port);
    sock_arr[sockfd].src_addr.sin_family = AF_INET;
    
    // check dst ip
    if(inet_pton(AF_INET, dst_ip, &sock_arr[sockfd].dst_addr.sin_addr) <= 0){
        errno = EINVAL;
        pthread_mutex_unlock(&sock_arr[sockfd].mutex);
        return -1;
    }

    // fill the destination address
    memset(&sock_arr[sockfd].dst_addr, 0, sizeof(struct sockaddr_in));
    sock_arr[sockfd].dst_addr.sin_port = htons(dst_port);
    sock_arr[sockfd].dst_addr.sin_family = AF_INET;

    // set the flag to indicate that socket is bound
    sock_arr[sockfd].is_bound = 1;
    // initksocket.c - will handle the bind request

    // wait for the bind request to be processed
    int bind_delay = 0;
    while(sock_arr[sockfd].bind_req && !sock_arr[sockfd].is_bound && bind_delay < 100){
        pthread_mutex_unlock(&sock_arr[sockfd].mutex);
        usleep(1000);
        pthread_mutex_lock(&sock_arr[sockfd].mutex);
        bind_delay++;
    }

    // if bind request is not processed
    if(!sock_arr[sockfd].is_bound){
        errno = ETIMEDOUT;
        pthread_mutex_unlock(&sock_arr[sockfd].mutex);
        return -1;
    }

    // unlock the socket mutex
    pthread_mutex_unlock(&sock_arr[sockfd].mutex);
    return 0;
}

ssize_t k_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen){
    // Get the ktp_socket_t array from shared memory
    ktp_socket_t* sock_arr = get_ktp_sockets();
    if (sock_arr == NULL) {
        return -1;
    }

    // check the socket
    if(sockfd < 0 || sockfd >= MAX_KTP_SOCK){
        errno = EBADF;
        return -1;
    }

    // lock the socket mutex
    pthread_mutex_lock(&sock_arr[sockfd].mutex);

    // check if the socket is allocated
    if(sock_arr[sockfd].is_alloc == 0){
        errno = EBADF;
        pthread_mutex_unlock(&sock_arr[sockfd].mutex);
        return -1;
    }

    // check if the socket is bound
    if(sock_arr[sockfd].is_bound == 0){
        errno = EINVAL;
        pthread_mutex_unlock(&sock_arr[sockfd].mutex);
        return -1;
    }

    // verify the destination address
    struct sockaddr_in* dest_addr_in = (struct sockaddr_in*)dest_addr;
    if(dest_addr_in->sin_family != AF_INET){
        errno = EINVAL;
        pthread_mutex_unlock(&sock_arr[sockfd].mutex);
        return -1;
    }

    // check if the destination address is same as the bound address
    if(sock_arr[sockfd].dst_addr.sin_addr.s_addr != dest_addr_in->sin_addr.s_addr || 
        sock_arr[sockfd].dst_addr.sin_port != dest_addr_in->sin_port){
        errno = EINVAL;
        pthread_mutex_unlock(&sock_arr[sockfd].mutex);
        return -1;
    }

    // find a free slot in the send buffer
    int next_write_pos = -1;
    for (int i = 0; i < SEND_BUFSIZE; i++) {
        int pos = (sock_arr[sockfd].swnd.base + sock_arr[sockfd].swnd.unack_cnt + i) % SEND_BUFSIZE;
        
        // Check if this slot is empty
        if (sock_arr[sockfd].send_buffer[pos][0] == 0) {
            next_write_pos = pos;
            break;
        }
    }
    
    // No free slot available
    if (next_write_pos == -1) {
        errno = ENOSPACE;
        pthread_mutex_unlock(&sock_arr[sockfd].mutex);
        return -1;
    }

    // allowed size of data
    size_t allowed_size = (len >= MSG_SIZE) ? MSG_SIZE : len;

    // fill the message
    memset(&sock_arr[sockfd].send_buffer[next_write_pos], 0, MSG_SIZE);
    memcpy(&sock_arr[sockfd].send_buffer[next_write_pos], buf, allowed_size);
    sock_arr[sockfd].send_buffer_occ[next_write_pos] = 1;

    // update the window -> sender will do

    // unlock the socket mutex
    pthread_mutex_unlock(&sock_arr[sockfd].mutex);
    return allowed_size;
}

ssize_t k_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen){
    // Get the ktp_socket_t array from shared memory
    ktp_socket_t* sock_arr = get_ktp_sockets();
    if (sock_arr == NULL) {
        return -1;
    }

    // check the socket
    if(sockfd < 0 || sockfd >= MAX_KTP_SOCK){
        errno = EBADF;
        return -1;
    }

    // lock the socket mutex
    pthread_mutex_lock(&sock_arr[sockfd].mutex);

    // check if the socket is allocated
    if(sock_arr[sockfd].is_alloc == 0){
        errno = EBADF;
        pthread_mutex_unlock(&sock_arr[sockfd].mutex);
        return -1;
    }

    // check if the socket is bound
    if(sock_arr[sockfd].is_bound == 0){
        errno = EINVAL;
        pthread_mutex_unlock(&sock_arr[sockfd].mutex);
        return -1;
    }

    // read pos
    int read_pos = sock_arr[sockfd].rwnd.buffer_read_pos;

    size_t allowed_size = (len >= MSG_SIZE) ? MSG_SIZE : len;
    allowed_size = strlen(sock_arr[sockfd].recv_buffer[read_pos]);
    memcpy(buf, sock_arr[sockfd].recv_buffer[read_pos], allowed_size);


    // clear nuf
    memset(sock_arr[sockfd].recv_buffer[read_pos], 0, MSG_SIZE);
    
    // update the read pos
    sock_arr[sockfd].rwnd.buffer_read_pos = (read_pos + 1) % RECV_BUFSIZE;

    // update buf occ
    sock_arr[sockfd].rwnd.buffer_occupied--;

    // update recv wnd
    sock_arr[sockfd].rwnd.size++;

    // unlock the socket mutex
    pthread_mutex_unlock(&sock_arr[sockfd].mutex);
    return allowed_size;
}

int k_close(int sockfd){
    // Get the ktp_socket_t array from shared memory
    ktp_socket_t* sock_arr = get_ktp_sockets();
    if (sock_arr == NULL) {
        return -1;
    }

    // check the socket
    if(sockfd < 0 || sockfd >= MAX_KTP_SOCK){
        errno = EBADF;
        return -1;
    }

    // lock the socket mutex
    pthread_mutex_lock(&sock_arr[sockfd].mutex);

    // check if the socket is allocated
    if(sock_arr[sockfd].is_alloc == 0){
        errno = EBADF;
        pthread_mutex_unlock(&sock_arr[sockfd].mutex);
        return -1;
    }
    
    sock_arr[sockfd].is_alloc = 0;
    sock_arr[sockfd].pid = 0;
    sock_arr[sockfd].is_bound = 0;

    // clear the send buffer
    for (int i = 0; i < SEND_BUFSIZE; i++) {
        memset(&sock_arr[sockfd].send_buffer[i], 0, MSG_SIZE);
        sock_arr[sockfd].send_buffer_occ[i] = 0;
    }

    // clear the receive buffer
    for (int i = 0; i < RECV_BUFSIZE; i++) {
        memset(&sock_arr[sockfd].recv_buffer[i], 0, MSG_SIZE);
    }

    // clear the window
    memset(&sock_arr[sockfd].swnd, 0, sizeof(swnd_t));
    memset(&sock_arr[sockfd].rwnd, 0, sizeof(rwnd_t));

    // clear rcv messages
    memset(&sock_arr[sockfd].rwnd.received_msgs, 0, RECV_BUFSIZE);

    // unlock the socket mutex
    pthread_mutex_unlock(&sock_arr[sockfd].mutex);

    return 0;
}

int dropMessage(float p){
    return (rand() < p * RAND_MAX);
}