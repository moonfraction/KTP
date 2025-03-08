#ifndef __KTP_SOCKET_H__
#define __KTP_SOCKET_H__

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/time.h>

/**
 * Protocol configuration constants
 */
/* Socket limits and buffer sizes */
#define KTP_MAX_SOCKETS       10    /* Maximum concurrent KTP sockets */
#define KTP_MSG_SIZE          512   /* Fixed message payload size */
#define KTP_RECV_BUFFER_SIZE  10    /* Receive buffer capacity */
#define KTP_SEND_BUFFER_SIZE  10    /* Send buffer capacity */
#define KTP_MAX_WINDOW_SIZE   10    /* Maximum sliding window size */

/* Protocol parameters */
#define KTP_TIMEOUT_SEC       5     /* Retransmission timeout in seconds */
#define KTP_PACKET_LOSS_PROB  0.15  /* Simulated packet loss probability */

/* Socket type identifier */
#define SOCK_KTP              1000  /* KTP socket type */

/* KTP-specific error codes */
#define E_KTP_NO_SPACE        1001  /* No buffer space available */
#define E_KTP_NOT_BOUND       1002  /* Socket not bound to a destination */
#define E_KTP_NO_MESSAGE      1003  /* No message available to read */

/* Message type identifiers */
typedef enum {
    KTP_TYPE_DATA = 0,
    KTP_TYPE_ACK  = 1
} ktp_msg_type_t;

/**
 * KTP protocol header structure
 * Contains control information for protocol operation
 */
typedef struct ktp_header {
    uint8_t  type;        /* Message type (DATA or ACK) */
    uint8_t  seq_num;     /* Sequence number */
    uint16_t rwnd;        /* Receiver window size */
    uint8_t  last_ack;    /* Last acknowledged sequence number */
} ktp_header_t;

/**
 * Complete KTP message structure including header and payload
 */
typedef struct ktp_message {
    ktp_header_t header;          /* Protocol control header */
    char         data[KTP_MSG_SIZE]; /* Message payload */
} ktp_message_t;

/**
 * KTP socket send window structure
 * Manages outgoing data flow and reliability
 */
typedef struct ktp_send_window {
    int             size;         /* Current window size */
    uint8_t         seq_nums[KTP_MAX_WINDOW_SIZE];    /* In-flight sequence numbers */
    struct timeval  send_times[KTP_MAX_WINDOW_SIZE];  /* Packet transmission timestamps */
    int             num_unacked;  /* Count of unacknowledged packets */
    int             base;         /* First unacknowledged packet index */
    int             next_seq_num; /* Next sequence number to use */
} ktp_send_window_t;

/**
 * KTP socket receive window structure
 * Manages incoming data flow and ordering
 */
typedef struct ktp_recv_window {
    int     size;               /* Current window size (free slots) */
    uint8_t expected_seq_num;   /* Next expected in-order sequence number */
    int     buffer_occupied;    /* Count of filled buffer slots */
    int     buffer_read_pos;    /* Next read position in buffer */
    int     buffer_write_pos;   /* Next write position in buffer */
    uint8_t received_msgs[KTP_RECV_BUFFER_SIZE]; /* Received message tracking */
    int     nospace_flag;       /* Buffer full indicator */
    uint8_t last_ack_sent;      /* Most recent ACK sequence number */
} ktp_recv_window_t;

/**
 * Main KTP socket structure
 */
typedef struct ktp_socket {
    /* Socket status */
    int             is_allocated;   /* 1=allocated, 0=free */
    pid_t           pid;            /* Owner process ID */
    int             udp_sockfd;     /* Underlying UDP socket */
    int             bind_requested; /* Binding request indicator */
    int             is_bound;       /* Bound state indicator */
    
    /* Socket addressing */
    struct sockaddr_in src_addr;    /* Local address */
    struct sockaddr_in dst_addr;    /* Remote address */
    
    /* Flow control structures */
    ktp_send_window_t swnd;         /* Send window */
    ktp_recv_window_t rwnd;         /* Receive window */
    
    /* Data buffers */
    char    send_buffer[KTP_SEND_BUFFER_SIZE][KTP_MSG_SIZE]; /* Outgoing message buffer */
    int     send_buffer_occ[KTP_SEND_BUFFER_SIZE];           /* Send buffer occupation flags */
    char    recv_buffer[KTP_RECV_BUFFER_SIZE][KTP_MSG_SIZE]; /* Incoming message buffer */
    
    /* Thread synchronization */
    pthread_mutex_t socket_mutex;   /* Socket access lock */
} ktp_socket_t;

/**
 * Client API function declarations
 */

/**
 * Creates a new KTP socket
 * 
 * @param domain    Address family (typically AF_INET)
 * @param type      Must be SOCK_KTP
 * @param protocol  Usually 0
 * @return          Socket descriptor on success, -1 on error with errno set
 */
int k_socket(int domain, int type, int protocol);

/**
 * Binds a KTP socket to local and remote endpoints
 * 
 * @param sockfd    KTP socket descriptor
 * @param src_ip    Source IP address string
 * @param src_port  Source port number
 * @param dst_ip    Destination IP address string
 * @param dst_port  Destination port number
 * @return          0 on success, -1 on error with errno set
 */
int k_bind(int sockfd, const char* src_ip, int src_port, 
           const char* dst_ip, int dst_port);

/**
 * Sends data via a KTP socket
 * 
 * @param sockfd     KTP socket descriptor
 * @param buf        Data buffer to send
 * @param len        Length of data to send
 * @param flags      Send flags (currently unused)
 * @param dest_addr  Destination address
 * @param addrlen    Address structure length
 * @return           Bytes sent on success, -1 on error with errno set
 */
ssize_t k_sendto(int sockfd, const void *buf, size_t len, int flags,
                const struct sockaddr *dest_addr, socklen_t addrlen);

/**
 * Receives data from a KTP socket
 * 
 * @param sockfd    KTP socket descriptor
 * @param buf       Buffer to store received data
 * @param len       Maximum bytes to receive
 * @param flags     Receive flags (currently unused)
 * @param src_addr  Source address storage (may be NULL)
 * @param addrlen   Address structure length pointer (may be NULL)
 * @return          Bytes received on success, -1 on error with errno set
 */
ssize_t k_recvfrom(int sockfd, void *buf, size_t len, int flags,
                  struct sockaddr *src_addr, socklen_t *addrlen);

/**
 * Closes a KTP socket and releases resources
 * 
 * @param sockfd    KTP socket descriptor to close
 * @return          0 on success, -1 on error with errno set
 */
int k_close(int sockfd);

/**
 * Simulates random packet loss for testing
 * 
 * @param p         Packet loss probability (0.0-1.0)
 * @return          1 if packet should be dropped, 0 otherwise
 */
int dropMessage(float p);

/**
 * Access shared memory segment containing KTP sockets
 * 
 * @return          Pointer to socket array in shared memory
 */
ktp_socket_t* get_ktp_sockets(void);

#endif /* __KTP_SOCKET_H__ */