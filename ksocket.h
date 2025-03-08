#ifndef KSOCKET_H
#define KSOCKET_H

#include <sys/socket.h>     // socket, bind, recvfrom, sendto
#include <errno.h>          // errno
#include <sys/types.h>      // pid_t
#include <netinet/in.h>     // sockaddr_in
#include <sys/time.h>       // timeval
#include <stdint.h>         // uint8_t, uint16_t

// global constanats
#define MAX_KTP_SOCK 10     // maximum number of sockets
#define MSG_SIZE 512        // maximum message size (bytes)
#define RECV_BUFSIZE 10     // receive buffer size (no of packets)
#define SEND_BUFSIZE 10     // send buffer size (no of packets)
#define WND_MAXSIZE 10      // maximum window size 
#define T 5                 // timeout value (sec)
#define P 0.1               // probability of packet loss

/* error codes */
#define ENOSPACE 1000
#define ENOTBOUND 1001
#define ENOMESSAGE 1002

/* sock type */
#define SOCK_KTP SOCK_DGRAM

/* message type */
#define MSG_DATA 0
#define MSG_ACK 1

/* message structure */
// header
typedef struct ktp_header {
    uint8_t type;           // data or ack
    uint8_t seq_num;        // sequence number
    uint8_t last_ack;       // seq no of last in-order received packet   
    uint16_t rwnd;          // receiver window size   
} ktp_header_t;

// message
typedef struct ktp_message {
    ktp_header_t header;
    char data[MSG_SIZE];
} ktp_message_t;


/* swnd*/
typedef struct sturct_swnd {
    int size;                               // cur window size
    int base;                               // base seq no of window
    int next_seq_num;                       // next seq no to be sent
    int unack_cnt;                          // number of unacknowledged packets
    int seq_nums[WND_MAXSIZE];              // seq no of packets that are sent, not acked
    struct timeval send_time[WND_MAXSIZE];  // time at which packet was sent
} swnd_t;

/* rwnd */
typedef struct sturct_rwnd {
    int size;                               // cur window size that is available to receive       
    uint8_t expected_seq_num;               // expected seq no of next packet
    uint8_t last_ack_sent;                  // seq no of last ack sent
    int buffer_occupied;                    // no of packets in buffer
    int buffer_read_pos;                    // read position in buffer
    int buffer_write_pos;                   // write position in buffer
    uint8_t received_msgs[RECV_BUFSIZE];    // seq no of received packets
    int nospace_flag;                       // flag to indicate no space in buffer
} rwnd_t;


/* KTP socket structure */
typedef struct ktp_socket {
    int is_alloc;                                  // flag to indicate if socket is allocated
    pid_t pid;                                  // process id of the process that created the socket               
    int udp_sockfd;                             // udp socket file descriptor
    int bind_req;                               // flag to indicate if bind request is made
    
    // connection details
    struct sockaddr_in src_addr;                // source address(IP and port)
    struct sockaddr_in dst_addr;                // destination address(IP and port)
    int is_bound;                               // flag to indicate if socket is bound
    
    swnd_t swnd;                                // sender window
    rwnd_t rwnd;                                // receiver window
    
    char send_buffer[SEND_BUFSIZE][MSG_SIZE];   // send buffer
    int send_buffer_occ[SEND_BUFSIZE];          // flag to indicate if buffer is occupied
    char recv_buffer[RECV_BUFSIZE][MSG_SIZE];   // receive buffer
    
    pthread_mutex_t mutex;               // mutex for socket
} ktp_socket_t;


// function prototypes
int k_socket(int domain, int type, int protocol);
int k_bind(int sockfd, const char* src_ip, int src_port, 
            const char* dst_ip, int dst_port);
ssize_t k_sendto(int sockfd, const void *buf, size_t len, 
        int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
ssize_t k_recvfrom(int sockfd, void *buf, size_t len, 
        int flags, struct sockaddr *src_addr, socklen_t *addrlen);
int k_close(int sockfd);
int dropMessage(float p);

// helper functions
ktp_socket_t* get_ktp_sockets(void);

#endif // KSOCKET_H