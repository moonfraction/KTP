/**
 * KTP Socket Implementation
 * 
 * Client-side networking layer for reliable messaging using the KTP protocol
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
static ktp_socket_t* ktpSocketArray = NULL;
static pthread_mutex_t globalMutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * Provides access to the shared memory segment containing KTP sockets
 * Uses double-checking pattern with mutex for thread safety
 * 
 * @return Pointer to the socket array, or NULL on error
 */
ktp_socket_t* get_ktp_sockets(void) 
{
    /* Fast path: return cached pointer if already attached */
    if (ktpSocketArray != NULL) 
    {
        return ktpSocketArray;
    }
    
    /* Lock for thread safety during initialization */
    pthread_mutex_lock(&globalMutex);
    
    /* Double-check after acquiring lock */
    if (ktpSocketArray != NULL) 
    {
        pthread_mutex_unlock(&globalMutex);
        return ktpSocketArray;
    }
    
    /* Generate the same key used by initksocket daemon */
    key_t shmKey = ftok("/tmp", 'K');
    if (shmKey == -1) 
    {
        perror("KTP Protocol: ftok operation failed");
        pthread_mutex_unlock(&globalMutex);
        return NULL;
    }
    
    /* Access the existing shared memory segment (don't create it) */
    int shmIdent = shmget(shmKey, sizeof(ktp_socket_t) * KTP_MAX_SOCKETS, 0666);
    if (shmIdent == -1) 
    {
        /* Shared memory not initialized yet - daemon not active? */
        pthread_mutex_unlock(&globalMutex);
        return NULL;
    }
    
    /* Attach to the shared memory segment */
    ktpSocketArray = (ktp_socket_t*)shmat(shmIdent, NULL, 0);
    if (ktpSocketArray == (void*)-1) 
    {
        perror("KTP Protocol: shared memory attachment failed");
        ktpSocketArray = NULL;
        pthread_mutex_unlock(&globalMutex);
        return NULL;
    }
    
    pthread_mutex_unlock(&globalMutex);
    return ktpSocketArray;
}

/**
 * Creates a new KTP socket
 * 
 * @param domain    Address family (typically AF_INET)
 * @param type      Must be SOCK_KTP
 * @param protocol  Usually 0
 * @return          Socket descriptor on success, -1 on error with errno set
 */
int k_socket(int domain, int type, int protocol) 
{
    /* Verify socket type */
    if (type != SOCK_KTP) 
    {
        errno = EINVAL;  /* Invalid argument */
        return -1;
    }
    
    /* Access the shared memory */
    ktp_socket_t* socketArray = get_ktp_sockets();
    if (socketArray == NULL) 
    {
        /* Shared memory not initialized */
        errno = EINVAL;
        return -1;
    }
    
    /* Lock for thread safety */
    pthread_mutex_lock(&globalMutex);
    
    /* Find an available socket slot */
    int sockHandle = -1;
    for (int i = 0; i < KTP_MAX_SOCKETS; i++) 
    {
        if (!socketArray[i].is_allocated && socketArray[i].udp_sockfd >= 0) 
        {
            sockHandle = i;
            break;
        }
    }
    
    /* Handle no available sockets */
    if (sockHandle < 0) 
    {
        pthread_mutex_unlock(&globalMutex);
        errno = E_KTP_NO_SPACE;
        return -1;
    }
    
    /* Initialize the socket */
    socketArray[sockHandle].is_allocated = 1;
    socketArray[sockHandle].pid = getpid();
    socketArray[sockHandle].is_bound = 0;
    
    /* Initialize the send window */
    socketArray[sockHandle].swnd.size = KTP_MAX_WINDOW_SIZE;
    socketArray[sockHandle].swnd.num_unacked = 0;
    socketArray[sockHandle].swnd.base = 1;
    socketArray[sockHandle].swnd.next_seq_num = 1;
    
    /* Initialize the receive window */
    socketArray[sockHandle].rwnd.size = KTP_RECV_BUFFER_SIZE;
    socketArray[sockHandle].rwnd.expected_seq_num = 1;
    socketArray[sockHandle].rwnd.buffer_occupied = 0;
    socketArray[sockHandle].rwnd.buffer_read_pos = 0;
    socketArray[sockHandle].rwnd.buffer_write_pos = 0;
    socketArray[sockHandle].rwnd.nospace_flag = 0;
    socketArray[sockHandle].rwnd.last_ack_sent = 0;
    
    printf("KTP Protocol: Process %d [socket %d] (UDP fd: %d)\n", 
        getpid(), sockHandle, socketArray[sockHandle].udp_sockfd);
    
    pthread_mutex_unlock(&globalMutex);
    return sockHandle;
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
        const char* dst_ip, int dst_port) 
{
    /* Get the shared memory array of KTP sockets */
    ktp_socket_t* socketArray = get_ktp_sockets();
    if (!socketArray) 
    {
        errno = EINVAL;  /* Invalid argument (shared memory not initialized) */
        return -1;
    }
    
    /* Validate the socket descriptor */
    if (sockfd < 0 || sockfd >= KTP_MAX_SOCKETS || !socketArray[sockfd].is_allocated) 
    {
        errno = EBADF;  /* Bad file descriptor */
        return -1;
    }
    
    /* Lock the socket mutex */
    pthread_mutex_lock(&socketArray[sockfd].socket_mutex);
    
    /* Configure source address */
    memset(&socketArray[sockfd].src_addr, 0, sizeof(struct sockaddr_in));
    socketArray[sockfd].src_addr.sin_family = AF_INET;
    socketArray[sockfd].src_addr.sin_port = htons(src_port);
    
    /* Convert source IP string to binary */
    if (inet_pton(AF_INET, src_ip, &(socketArray[sockfd].src_addr.sin_addr)) <= 0) 
    {
        pthread_mutex_unlock(&socketArray[sockfd].socket_mutex);
        errno = EINVAL;  /* Invalid address */
        return -1;
    }
    
    /* Configure destination address */
    memset(&socketArray[sockfd].dst_addr, 0, sizeof(struct sockaddr_in));
    socketArray[sockfd].dst_addr.sin_family = AF_INET;
    socketArray[sockfd].dst_addr.sin_port = htons(dst_port);
    
    /* Convert destination IP string to binary */
    if (inet_pton(AF_INET, dst_ip, &(socketArray[sockfd].dst_addr.sin_addr)) <= 0) 
    {
        pthread_mutex_unlock(&socketArray[sockfd].socket_mutex);
        errno = EINVAL;  /* Invalid address */
        return -1;
    }
    
    /* Set binding request flag - daemon receiver thread will handle binding */
    socketArray[sockfd].bind_requested = 1;
    
    /* Wait for the binding operation to complete (with timeout) */
    const int MAX_BINDING_TRIES = 50;  /* 5 seconds total timeout */
    int bindingCounter = 0;
    
    while (socketArray[sockfd].bind_requested && 
        !socketArray[sockfd].is_bound && 
        bindingCounter < MAX_BINDING_TRIES) 
    {
        /* Release mutex while waiting */
        pthread_mutex_unlock(&socketArray[sockfd].socket_mutex);
        usleep(100000);  /* 100ms */
        pthread_mutex_lock(&socketArray[sockfd].socket_mutex);
        bindingCounter++;
    }
    
    /* Check if binding succeeded */
    int bindSuccess = socketArray[sockfd].is_bound;
    pthread_mutex_unlock(&socketArray[sockfd].socket_mutex);
    
    if (!bindSuccess) 
    {
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
                const struct sockaddr *dest_addr, socklen_t addrlen) 
{
    /* Get the shared memory array */
    ktp_socket_t* socketArray = get_ktp_sockets();
    if (!socketArray) 
    {
        errno = EINVAL;
        return -1;
    }
    
    /* Validate socket descriptor */
    if (sockfd < 0 || sockfd >= KTP_MAX_SOCKETS || !socketArray[sockfd].is_allocated) 
    {
        errno = EBADF;
        return -1;
    }
    
    /* Lock the socket mutex */
    pthread_mutex_lock(&socketArray[sockfd].socket_mutex);
    
    /* Ensure socket is bound */
    if (!socketArray[sockfd].is_bound) 
    {
        pthread_mutex_unlock(&socketArray[sockfd].socket_mutex);
        errno = E_KTP_NOT_BOUND;
        return -1;
    }
    
    /* Verify destination address matches the bound destination */
    const struct sockaddr_in* destAddr = (const struct sockaddr_in*)dest_addr;
    if (destAddr->sin_addr.s_addr != socketArray[sockfd].dst_addr.sin_addr.s_addr || 
        destAddr->sin_port != socketArray[sockfd].dst_addr.sin_port) 
    {
        pthread_mutex_unlock(&socketArray[sockfd].socket_mutex);
        errno = E_KTP_NOT_BOUND;
        return -1;
    }
    
    /* Find a free slot in the send buffer */
    int nextWritePos = -1;
    const int baseIdx = socketArray[sockfd].swnd.base;
    const int numWaiting = socketArray[sockfd].swnd.num_unacked;
    
    /* Search for an empty slot after the current window */
    for (int i = 0; i < KTP_SEND_BUFFER_SIZE; i++) 
    {
        int bufPos = (baseIdx + numWaiting + i) % KTP_SEND_BUFFER_SIZE;
        
        if (socketArray[sockfd].send_buffer_occ[bufPos] == 0) 
        {
            nextWritePos = bufPos;
            break;
        }
    }
    
    /* Handle buffer full condition */
    if (nextWritePos == -1) 
    {
        pthread_mutex_unlock(&socketArray[sockfd].socket_mutex);
        errno = E_KTP_NO_SPACE;
        return -1;
    }
    
    /* Determine message size (respect buffer size limit) */
    size_t bytesToWrite = (len < KTP_MSG_SIZE) ? len : KTP_MSG_SIZE;
    
    /* Copy data to the send buffer */
    memset(socketArray[sockfd].send_buffer[nextWritePos], 0, KTP_MSG_SIZE);
    memcpy(socketArray[sockfd].send_buffer[nextWritePos], buf, bytesToWrite);
    
    /* Mark buffer position as occupied */
    socketArray[sockfd].send_buffer_occ[nextWritePos] = 1;
    
    /* Unlock before returning */
    pthread_mutex_unlock(&socketArray[sockfd].socket_mutex);
    
    /* Return the number of bytes queued for sending */
    return bytesToWrite;
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
                struct sockaddr *src_addr, socklen_t *addrlen) 
{
    /* Get the shared memory array */
    ktp_socket_t* socketArray = get_ktp_sockets();
    if (!socketArray) 
    {
        errno = EINVAL;
        return -1;
    }
    
    /* Validate socket descriptor */
    if (sockfd < 0 || sockfd >= KTP_MAX_SOCKETS || !socketArray[sockfd].is_allocated) 
    {
        errno = EBADF;
        return -1;
    }
    
    /* Lock the socket mutex */
    pthread_mutex_lock(&socketArray[sockfd].socket_mutex);
    
    /* Check if there are any messages available */
    if (socketArray[sockfd].rwnd.buffer_occupied <= 0) 
    {
        pthread_mutex_unlock(&socketArray[sockfd].socket_mutex);
        errno = E_KTP_NO_MESSAGE;
        return -1;
    }
    
    /* Get the current read position */
    int readPos = socketArray[sockfd].rwnd.buffer_read_pos;
    
    /* Calculate bytes to copy (respect buffer limits) */
    size_t msgLength = strlen(socketArray[sockfd].recv_buffer[readPos]);
    size_t bytesToCopy = (len < msgLength) ? len : msgLength;
    
    /* Copy data to user's buffer */
    memcpy(buf, socketArray[sockfd].recv_buffer[readPos], bytesToCopy);
    
    /* Clear the buffer slot */
    memset(socketArray[sockfd].recv_buffer[readPos], 0, KTP_MSG_SIZE);
    
    /* Update buffer state */
    socketArray[sockfd].rwnd.buffer_read_pos = (readPos + 1) % KTP_RECV_BUFFER_SIZE;
    socketArray[sockfd].rwnd.buffer_occupied--;
    
    /* Update flow control state */
    socketArray[sockfd].rwnd.size++;
    
    pthread_mutex_unlock(&socketArray[sockfd].socket_mutex);
    return bytesToCopy;
}

/**
 * Closes a KTP socket and releases resources
 * 
 * @param sockfd    KTP socket descriptor to close
 * @return          0 on success, -1 on error with errno set
 */
int k_close(int sockfd) 
{
    /* Get the shared memory array */
    ktp_socket_t* socketArray = get_ktp_sockets();
    if (!socketArray) 
    {
        errno = EINVAL;
        return -1;
    }
    
    /* Validate socket descriptor */
    if (sockfd < 0 || sockfd >= KTP_MAX_SOCKETS || !socketArray[sockfd].is_allocated) 
    {
        errno = EBADF;
        return -1;
    }
    
    /* Lock the socket mutex */
    pthread_mutex_lock(&socketArray[sockfd].socket_mutex);
    
    /* Release the socket */
    socketArray[sockfd].is_allocated = 0;
    socketArray[sockfd].pid = 0;
    socketArray[sockfd].is_bound = 0;
    
    /* Reset send buffer */
    for (int i = 0; i < KTP_SEND_BUFFER_SIZE; i++) 
    {
        memset(socketArray[sockfd].send_buffer[i], 0, KTP_MSG_SIZE);
        socketArray[sockfd].send_buffer_occ[i] = 0;
    }
    
    /* Reset receive buffer */
    for (int i = 0; i < KTP_RECV_BUFFER_SIZE; i++) 
    {
        memset(socketArray[sockfd].recv_buffer[i], 0, KTP_MSG_SIZE);
    }
    
    /* Reset message tracking */
    memset(socketArray[sockfd].rwnd.received_msgs, 0, 
        sizeof(socketArray[sockfd].rwnd.received_msgs));
    
    /* Clear window structures */
    memset(&socketArray[sockfd].swnd, 0, sizeof(socketArray[sockfd].swnd));
    memset(&socketArray[sockfd].rwnd, 0, sizeof(socketArray[sockfd].rwnd));
    
    pthread_mutex_unlock(&socketArray[sockfd].socket_mutex);
    return 0;
}

/**
 * Simulates random packet loss for testing
 * 
 * @param p    Packet loss probability (0.0-1.0)
 * @return     1 if packet should be dropped, 0 otherwise
 */
int dropMessage(float p) 
{
    /* Validate probability range */
    if (p < 0.0f || p > 1.0f) 
    {
        return 0;  /* Invalid probability, default to no loss */
    }
    
    /* Generate random number and compare with threshold */
    float randValue = (float)rand() / RAND_MAX;
    return (randValue < p) ? 1 : 0;
}