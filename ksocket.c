/**
 * KTP Socket Implementation
 * 
 * Client-side implementation of the KTP protocol functions
 */

 #include "ksocket.h"
 #include <errno.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <sys/types.h>
 #include <sys/socket.h>
 #include <sys/ipc.h>
 #include <sys/shm.h>
 #include <arpa/inet.h>
 
 /* Global variables */
 static ktp_socket_t* ktp_sockets = NULL;
 static pthread_mutex_t global_mutex = PTHREAD_MUTEX_INITIALIZER;
 
 /**
  * Provides access to the shared memory segment containing KTP sockets
  * Uses double-checking pattern with mutex for thread safety
  * 
  * @return Pointer to the socket array, or NULL on error
  */
 ktp_socket_t* get_ktp_sockets(void) {
     /* Fast path: return cached pointer if already attached */
     if (ktp_sockets != NULL) {
         return ktp_sockets;
     }
     
     /* Lock for thread safety during initialization */
     pthread_mutex_lock(&global_mutex);
     
     /* Double-check after acquiring lock */
     if (ktp_sockets != NULL) {
         pthread_mutex_unlock(&global_mutex);
         return ktp_sockets;
     }
     
     /* Generate the same key used by initksocket daemon */
     key_t key = ftok("/tmp", 'K');
     if (key == -1) {
         perror("KTP: ftok failed");
         pthread_mutex_unlock(&global_mutex);
         return NULL;
     }
     
     /* Access the existing shared memory segment (don't create it) */
     int shmid = shmget(key, sizeof(ktp_socket_t) * KTP_MAX_SOCKETS, 0666);
     if (shmid == -1) {
         /* Shared memory not initialized yet - initksocket daemon not running? */
         pthread_mutex_unlock(&global_mutex);
         return NULL;
     }
     
     /* Attach to the shared memory segment */
     ktp_sockets = (ktp_socket_t*)shmat(shmid, NULL, 0);
     if (ktp_sockets == (void*)-1) {
         perror("KTP: shmat failed");
         ktp_sockets = NULL;
         pthread_mutex_unlock(&global_mutex);
         return NULL;
     }
     
     pthread_mutex_unlock(&global_mutex);
     return ktp_sockets;
 }
 
 /**
  * Creates a new KTP socket
  * 
  * @param domain    Address family (typically AF_INET)
  * @param type      Must be SOCK_KTP
  * @param protocol  Usually 0
  * @return          Socket descriptor on success, -1 on error with errno set
  */
 int k_socket(int domain, int type, int protocol) {
     /* Verify socket type */
     if (type != SOCK_KTP) {
         errno = EINVAL;  /* Invalid argument */
         return -1;
     }
     
     /* Access the shared memory */
     ktp_socket_t* sockets = get_ktp_sockets();
     if (sockets == NULL) {
         /* Shared memory not initialized */
         errno = EINVAL;
         return -1;
     }
     
     /* Lock for thread safety */
     pthread_mutex_lock(&global_mutex);
     
     /* Find an available socket slot */
     int sockfd = -1;
     for (int i = 0; i < KTP_MAX_SOCKETS; i++) {
         if (!sockets[i].is_allocated && sockets[i].udp_sockfd >= 0) {
             sockfd = i;
             break;
         }
     }
     
     /* Handle no available sockets */
     if (sockfd < 0) {
         pthread_mutex_unlock(&global_mutex);
         errno = E_KTP_NO_SPACE;
         return -1;
     }
     
     /* Initialize the socket */
     sockets[sockfd].is_allocated = 1;
     sockets[sockfd].pid = getpid();
     sockets[sockfd].is_bound = 0;
     
     /* Initialize the send window */
     sockets[sockfd].swnd.size = KTP_MAX_WINDOW_SIZE;
     sockets[sockfd].swnd.num_unacked = 0;
     sockets[sockfd].swnd.base = 1;
     sockets[sockfd].swnd.next_seq_num = 1;
     
     /* Initialize the receive window */
     sockets[sockfd].rwnd.size = KTP_RECV_BUFFER_SIZE;
     sockets[sockfd].rwnd.expected_seq_num = 1;
     sockets[sockfd].rwnd.buffer_occupied = 0;
     sockets[sockfd].rwnd.buffer_read_pos = 0;
     sockets[sockfd].rwnd.buffer_write_pos = 0;
     sockets[sockfd].rwnd.nospace_flag = 0;
     sockets[sockfd].rwnd.last_ack_sent = 0;
     
     printf("KTP: Process %d allocated socket %d with UDP fd %d\n", 
            getpid(), sockfd, sockets[sockfd].udp_sockfd);
     
     pthread_mutex_unlock(&global_mutex);
     return sockfd;
 }
 
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
            const char* dst_ip, int dst_port) {
     /* Get the shared memory array of KTP sockets */
     ktp_socket_t* sockets = get_ktp_sockets();
     if (!sockets) {
         errno = EINVAL;  /* Invalid argument (shared memory not initialized) */
         return -1;
     }
     
     /* Validate the socket descriptor */
     if (sockfd < 0 || sockfd >= KTP_MAX_SOCKETS || !sockets[sockfd].is_allocated) {
         errno = EBADF;  /* Bad file descriptor */
         return -1;
     }
     
     /* Lock the socket mutex */
     pthread_mutex_lock(&sockets[sockfd].socket_mutex);
     
     /* Configure source address */
     memset(&sockets[sockfd].src_addr, 0, sizeof(struct sockaddr_in));
     sockets[sockfd].src_addr.sin_family = AF_INET;
     sockets[sockfd].src_addr.sin_port = htons(src_port);
     
     /* Convert source IP string to binary */
     if (inet_pton(AF_INET, src_ip, &(sockets[sockfd].src_addr.sin_addr)) <= 0) {
         pthread_mutex_unlock(&sockets[sockfd].socket_mutex);
         errno = EINVAL;  /* Invalid address */
         return -1;
     }
     
     /* Configure destination address */
     memset(&sockets[sockfd].dst_addr, 0, sizeof(struct sockaddr_in));
     sockets[sockfd].dst_addr.sin_family = AF_INET;
     sockets[sockfd].dst_addr.sin_port = htons(dst_port);
     
     /* Convert destination IP string to binary */
     if (inet_pton(AF_INET, dst_ip, &(sockets[sockfd].dst_addr.sin_addr)) <= 0) {
         pthread_mutex_unlock(&sockets[sockfd].socket_mutex);
         errno = EINVAL;  /* Invalid address */
         return -1;
     }
     
     /* Set binding request flag - initksocket receiver thread will handle binding */
     sockets[sockfd].bind_requested = 1;
     
     /* Wait for the binding operation to complete (with timeout) */
     const int MAX_BIND_WAIT = 50;  /* 5 seconds total timeout */
     int timeout_counter = 0;
     
     while (sockets[sockfd].bind_requested && 
            !sockets[sockfd].is_bound && 
            timeout_counter < MAX_BIND_WAIT) {
         /* Release mutex while waiting */
         pthread_mutex_unlock(&sockets[sockfd].socket_mutex);
         usleep(100000);  /* 100ms */
         pthread_mutex_lock(&sockets[sockfd].socket_mutex);
         timeout_counter++;
     }
     
     /* Check if binding succeeded */
     int success = sockets[sockfd].is_bound;
     pthread_mutex_unlock(&sockets[sockfd].socket_mutex);
     
     if (!success) {
         errno = ETIMEDOUT;  /* Timed out waiting for binding */
         return -1;
     }
     
     return 0;  /* Successfully bound */
 }
 
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
                 const struct sockaddr *dest_addr, socklen_t addrlen) {
     /* Get the shared memory array */
     ktp_socket_t* sockets = get_ktp_sockets();
     if (!sockets) {
         errno = EINVAL;
         return -1;
     }
     
     /* Validate socket descriptor */
     if (sockfd < 0 || sockfd >= KTP_MAX_SOCKETS || !sockets[sockfd].is_allocated) {
         errno = EBADF;
         return -1;
     }
     
     /* Lock the socket mutex */
     pthread_mutex_lock(&sockets[sockfd].socket_mutex);
     
     /* Ensure socket is bound */
     if (!sockets[sockfd].is_bound) {
         pthread_mutex_unlock(&sockets[sockfd].socket_mutex);
         errno = E_KTP_NOT_BOUND;
         return -1;
     }
     
     /* Verify destination address matches the bound destination */
     const struct sockaddr_in* addr = (const struct sockaddr_in*)dest_addr;
     if (addr->sin_addr.s_addr != sockets[sockfd].dst_addr.sin_addr.s_addr || 
         addr->sin_port != sockets[sockfd].dst_addr.sin_port) {
         pthread_mutex_unlock(&sockets[sockfd].socket_mutex);
         errno = E_KTP_NOT_BOUND;
         return -1;
     }
     
     /* Find a free slot in the send buffer */
     int next_write_pos = -1;
     const int base_idx = sockets[sockfd].swnd.base;
     const int num_unacked = sockets[sockfd].swnd.num_unacked;
     
     /* Search for an empty slot after the current window */
     for (int i = 0; i < KTP_SEND_BUFFER_SIZE; i++) {
         int pos = (base_idx + num_unacked + i) % KTP_SEND_BUFFER_SIZE;
         
         if (sockets[sockfd].send_buffer_occ[pos] == 0) {
             next_write_pos = pos;
             break;
         }
     }
     
     /* Handle buffer full condition */
     if (next_write_pos == -1) {
         pthread_mutex_unlock(&sockets[sockfd].socket_mutex);
         errno = E_KTP_NO_SPACE;
         return -1;
     }
     
     /* Determine message size (respect buffer size limit) */
     size_t bytes_to_write = (len < KTP_MSG_SIZE) ? len : KTP_MSG_SIZE;
     
     /* Copy data to the send buffer */
     memset(sockets[sockfd].send_buffer[next_write_pos], 0, KTP_MSG_SIZE);
     memcpy(sockets[sockfd].send_buffer[next_write_pos], buf, bytes_to_write);
     
     /* Mark buffer position as occupied */
     sockets[sockfd].send_buffer_occ[next_write_pos] = 1;
     
     /* Unlock before returning */
     pthread_mutex_unlock(&sockets[sockfd].socket_mutex);
     
     /* Return the number of bytes queued for sending */
     return bytes_to_write;
 }
 
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
                   struct sockaddr *src_addr, socklen_t *addrlen) {
     /* Get the shared memory array */
     ktp_socket_t* sockets = get_ktp_sockets();
     if (!sockets) {
         errno = EINVAL;
         return -1;
     }
     
     /* Validate socket descriptor */
     if (sockfd < 0 || sockfd >= KTP_MAX_SOCKETS || !sockets[sockfd].is_allocated) {
         errno = EBADF;
         return -1;
     }
     
     /* Lock the socket mutex */
     pthread_mutex_lock(&sockets[sockfd].socket_mutex);
     
     /* Check if there are any messages available */
     if (sockets[sockfd].rwnd.buffer_occupied <= 0) {
         pthread_mutex_unlock(&sockets[sockfd].socket_mutex);
         errno = E_KTP_NO_MESSAGE;
         return -1;
     }
     
     /* Get the current read position */
     int read_pos = sockets[sockfd].rwnd.buffer_read_pos;
     
     /* Calculate bytes to copy (respect buffer limits) */
     size_t message_len = strlen(sockets[sockfd].recv_buffer[read_pos]);
     size_t bytes_to_copy = (len < message_len) ? len : message_len;
     
     /* Copy data to user's buffer */
     memcpy(buf, sockets[sockfd].recv_buffer[read_pos], bytes_to_copy);
     
     /* Clear the buffer slot */
     memset(sockets[sockfd].recv_buffer[read_pos], 0, KTP_MSG_SIZE);
     
     /* Update buffer state */
     sockets[sockfd].rwnd.buffer_read_pos = (read_pos + 1) % KTP_RECV_BUFFER_SIZE;
     sockets[sockfd].rwnd.buffer_occupied--;
     
     /* Update flow control state */
     sockets[sockfd].rwnd.size++;
     
     pthread_mutex_unlock(&sockets[sockfd].socket_mutex);
     return bytes_to_copy;
 }
 
 /**
  * Closes a KTP socket and releases resources
  * 
  * @param sockfd    KTP socket descriptor to close
  * @return          0 on success, -1 on error with errno set
  */
 int k_close(int sockfd) {
     /* Get the shared memory array */
     ktp_socket_t* sockets = get_ktp_sockets();
     if (!sockets) {
         errno = EINVAL;
         return -1;
     }
     
     /* Validate socket descriptor */
     if (sockfd < 0 || sockfd >= KTP_MAX_SOCKETS || !sockets[sockfd].is_allocated) {
         errno = EBADF;
         return -1;
     }
     
     /* Lock the socket mutex */
     pthread_mutex_lock(&sockets[sockfd].socket_mutex);
     
     /* Release the socket */
     sockets[sockfd].is_allocated = 0;
     sockets[sockfd].pid = 0;
     sockets[sockfd].is_bound = 0;
     
     /* Reset send buffer */
     for (int i = 0; i < KTP_SEND_BUFFER_SIZE; i++) {
         memset(sockets[sockfd].send_buffer[i], 0, KTP_MSG_SIZE);
         sockets[sockfd].send_buffer_occ[i] = 0;
     }
     
     /* Reset receive buffer */
     for (int i = 0; i < KTP_RECV_BUFFER_SIZE; i++) {
         memset(sockets[sockfd].recv_buffer[i], 0, KTP_MSG_SIZE);
     }
     
     /* Reset message tracking */
     memset(sockets[sockfd].rwnd.received_msgs, 0, sizeof(sockets[sockfd].rwnd.received_msgs));
     
     /* Clear window structures */
     memset(&sockets[sockfd].swnd, 0, sizeof(sockets[sockfd].swnd));
     memset(&sockets[sockfd].rwnd, 0, sizeof(sockets[sockfd].rwnd));
     
     pthread_mutex_unlock(&sockets[sockfd].socket_mutex);
     return 0;
 }
 
 /**
  * Simulates random packet loss for testing
  * 
  * @param p    Packet loss probability (0.0-1.0)
  * @return     1 if packet should be dropped, 0 otherwise
  */
 int dropMessage(float p) {
     /* Validate probability range */
     if (p < 0.0f || p > 1.0f) {
         return 0;  /* Invalid probability, default to no loss */
     }
     
     /* Generate random number and compare with threshold */
     float rand_val = (float)rand() / RAND_MAX;
     return (rand_val < p) ? 1 : 0;
 }