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
static ktp_socket_t *ktpSocketArray = NULL;
static pthread_mutex_t globalMutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * Establishes connection to protocol transport memory region
 *
 * This function connects to the shared memory segment containing transport
 * socket structures with thread-safe initialization pattern.
 *
 * @return Transport socket array pointer or NULL on failure
 */
ktp_socket_t *get_KTPsock_arr(void)
{
    // Quick check for already established connection
    if (ktpSocketArray)
        return ktpSocketArray;

    // Synchronize thread access during initialization
    if (pthread_mutex_lock(&globalMutex) != 0)
    {
        fprintf(stderr, "KTP: Synchronization failed\n");
        return NULL;
    }

    // Re-verification after lock acquisition (double-check pattern)
    if (ktpSocketArray)
    {
        pthread_mutex_unlock(&globalMutex);
        return ktpSocketArray;
    }

    // Create memory region identifier
    const char *PATH_COMPONENT = "/";
    const int PROJECT_ID = 'A';

    key_t memoryKey = ftok(PATH_COMPONENT, PROJECT_ID);
    if (memoryKey == -1)
    {
        fprintf(stderr, "KTP: Memory key generation failed (%s)\n",
                strerror(errno));
        pthread_mutex_unlock(&globalMutex);
        return NULL;
    }

    // Locate existing memory segment
    const size_t REGION_SIZE = sizeof(ktp_socket_t) * KTP_MAX_SOCKETS;
    const int ACCESS_MODE = 0666; // Same permissions as service

    int memoryId = shmget(memoryKey, REGION_SIZE, ACCESS_MODE);
    if (memoryId == -1)
    {
        fprintf(stderr, "KTP: Memory segment not found - service may not be running\n");
        pthread_mutex_unlock(&globalMutex);
        return NULL;
    }

    // Map memory region into process space
    void *memoryRegion = shmat(memoryId, NULL, 0);
    if (memoryRegion == (void *)-1)
    {
        fprintf(stderr, "KTP: Memory attachment failed: %s\n",
                strerror(errno));
        pthread_mutex_unlock(&globalMutex);
        return NULL;
    }

    // Store successful connection
    ktpSocketArray = (ktp_socket_t *)memoryRegion;

    // Output success message (new feature)
    fprintf(stdout, "KTP: Successfully connected to socket memory array\n");

    // Release synchronization lock
    pthread_mutex_unlock(&globalMutex);

    return ktpSocketArray;
}

/**
 * Creates a transport protocol Socket
 *
 * Allocates and initializes a new transport protocol Socket for
 * reliable communication over unreliable channels.
 *
 * @param domain     Protocol domain (typically AF_INET for Internet protocols)
 * @param type Must be SOCK_KTP for this transport layer
 * @param protocol    Reserved for future use (pass 0)
 * @return           Non-negative Socket ID on success, -1 on failure with errno set
 */

int k_socket(int domain, int type, int protocol)
{
    // Validate requested Socket type
    if (type != SOCK_KTP)
    {
        fprintf(stderr, "KTP: Unsupported socket type. Must use SOCK_KTP.\n");
        errno = EINVAL; // Invalid argument
        return -1;
    }

    // Access transport memory region
    ktp_socket_t *SocketArray = get_KTPsock_arr();
    if (SocketArray == NULL)
    {
        fprintf(stderr, "KTP: Failed to connect to transport memory region\n");
        errno = ENODATA; // No data available (KTP not running)
        return -1;
    }

    // Begin critical section for Socket allocation
    int status = pthread_mutex_lock(&globalMutex);
    if (status != 0)
    {
        fprintf(stderr, "KTP: Thread synchronization failed: %s\n", strerror(status));
        errno = EAGAIN; // Resource temporarily unavailable
        return -1;
    }

    // Find available Socket slot using reverse search
    // (Starting from high indices often finds free slots faster)
    int SocketId = -1;
    for (int idx = KTP_MAX_SOCKETS - 1; idx >= 0; idx--)
    {
        // Check if slot is free and has a valid UDP socket
        if (!SocketArray[idx].is_allocated && SocketArray[idx].udp_sockfd >= 0)
        {
            SocketId = idx;
            break;
        }
    }

    // Handle Socket allocation failure
    if (SocketId == -1)
    {
        pthread_mutex_unlock(&globalMutex);
        fprintf(stderr, "KTP: No socket available (max=%d)\n", KTP_MAX_SOCKETS);
        errno = E_KTP_NO_SPACE;
        return -1;
    }

    // Claim and initialize Socket
    ktp_socket_t *Socket = &SocketArray[SocketId];

    // Set basic Socket properties
    Socket->is_allocated = 1;   // Mark as allocated
    Socket->pid = getpid();     // Record owning process
    Socket->is_bound = 0;       // Not bound initially
    Socket->bind_requested = 0; // No binding requested yet

    // Configure transmission control state
    Socket->swnd.size = KTP_MAX_WINDOW_SIZE; // Begin with max window
    Socket->swnd.num_unacked = 0;            // No unacknowledged packets
    Socket->swnd.base = 1;                   // Start at sequence 1
    Socket->swnd.next_seq_num = 1;           // First packet will be sequence 1

    // Configure reception control state
    Socket->rwnd.size = KTP_RECV_BUFFER_SIZE; // Full receive window initially
    Socket->rwnd.expected_seq_num = 1;        // Expect first packet with sequence 1
    Socket->rwnd.buffer_occupied = 0;         // Buffer starts empty
    Socket->rwnd.buffer_read_pos = 0;         // Start reading at position 0
    Socket->rwnd.buffer_write_pos = 0;        // Start writing at position 0
    Socket->rwnd.nospace_flag = 0;            // Buffer has space initially
    Socket->rwnd.last_ack_sent = 0;           // No packets acknowledged yet

    // Clear receive tracking array
    memset(Socket->rwnd.received_msgs, 0, sizeof(Socket->rwnd.received_msgs));

    // Log successful Socket creation with detailed info
    fprintf(stdout, "KTP: Created scoket %d for process %d [UDP socket: %d]\n",
            SocketId, Socket->pid, Socket->udp_sockfd);

    // End critical section
    pthread_mutex_unlock(&globalMutex);

    // Return the new Socket ID
    return SocketId;
}

/**
 * Associates a transport Socket with network addresses
 *
 * This function configures the connection parameters for a transport Socket
 * and initiates the actual binding process through the daemon service.
 *
 * @param sockfd     Transport Socket identifier
 * @param src_ip    Local IP address string
 * @param src_port       Local port number
 * @param dst_ip   Remote IP address string
 * @param dst_port      Remote port number
 * @return                0 when successful, -1 on failure with errno set
 */

int k_bind(int sockfd, const char *src_ip, int src_port,
           const char *dst_ip, int dst_port)
{
    int result = -1;
    struct in_addr local_binary, remote_binary;

    // Validate parameters and access shared state
    ktp_socket_t *SocketArray = get_KTPsock_arr();
    if (!SocketArray)
    {
        fprintf(stderr, "KTP: Cannot access KTP socket array\n");
        errno = ENOTCONN; // Not connected to service
        return -1;
    }

    // Validate Socket identifier
    if (sockfd < 0 || sockfd >= KTP_MAX_SOCKETS)
    {
        fprintf(stderr, "KTP: Invalid Socket identifier: %d\n", sockfd);
        errno = EBADF; // Bad file descriptor
        return -1;
    }

    // Verify Socket is allocated and available
    if (!SocketArray[sockfd].is_allocated)
    {
        fprintf(stderr, "KTP: Socket %d not allocated\n", sockfd);
        errno = EINVAL;
        return -1;
    }

    // Acquire exclusive access to Socket
    if (pthread_mutex_lock(&SocketArray[sockfd].socket_mutex) != 0)
    {
        fprintf(stderr, "KTP: Failed to lock Socket %d mutex\n", sockfd);
        errno = EAGAIN;
        return -1;
    }

    // Parse network addresses
    if (inet_pton(AF_INET, src_ip, &local_binary) <= 0)
    {
        fprintf(stderr, "KTP: Invalid local address format: %s\n", src_ip);
        pthread_mutex_unlock(&SocketArray[sockfd].socket_mutex);
        errno = EINVAL;
        return -1;
    }

    if (inet_pton(AF_INET, dst_ip, &remote_binary) <= 0)
    {
        fprintf(stderr, "KTP: Invalid remote address format: %s\n", dst_ip);
        pthread_mutex_unlock(&SocketArray[sockfd].socket_mutex);
        errno = EINVAL;
        return -1;
    }

    // Configure source address structure
    struct sockaddr_in *localSockAddr = &SocketArray[sockfd].src_addr;
    memset(localSockAddr, 0, sizeof(struct sockaddr_in));
    localSockAddr->sin_family = AF_INET;
    localSockAddr->sin_port = htons(src_port);
    localSockAddr->sin_addr = local_binary;

    // Configure destination address structure
    struct sockaddr_in *remoteSockAddr = &SocketArray[sockfd].dst_addr;
    memset(remoteSockAddr, 0, sizeof(struct sockaddr_in));
    remoteSockAddr->sin_family = AF_INET;
    remoteSockAddr->sin_port = htons(dst_port);
    remoteSockAddr->sin_addr = remote_binary;

    // Request binding operation from daemon
    fprintf(stdout, "KTP: Requesting binding for Socket %d (%s:%d → %s:%d)\n",
            sockfd, src_ip, src_port, dst_ip, dst_port);
    SocketArray[sockfd].bind_requested = 1;

    // Wait for binding confirmation with adaptive backoff
    const int MAX_WAIT_TIME_MS = 5000; // 5 second timeout
    int elapsedTimeMs = 0;
    int waitIntervalMs = 50; // Start with 50ms check interval

    while (!SocketArray[sockfd].is_bound &&
           SocketArray[sockfd].bind_requested &&
           elapsedTimeMs < MAX_WAIT_TIME_MS)
    {

        // Release lock during wait to avoid blocking daemon
        pthread_mutex_unlock(&SocketArray[sockfd].socket_mutex);

        // Wait for specified interval
        usleep(waitIntervalMs * 1000);
        elapsedTimeMs += waitIntervalMs;

        // Adaptive backoff - increase wait time gradually
        if (waitIntervalMs < 200)
            waitIntervalMs += 25;

        // Re-acquire lock to check binding status
        pthread_mutex_lock(&SocketArray[sockfd].socket_mutex);
    }

    //  Determine operation outcome
    if (SocketArray[sockfd].is_bound)
    {
        fprintf(stdout, "KTP: Socket %d successfully bound\n", sockfd);
        result = 0; // Success
    }
    else
    {
        fprintf(stderr, "KTP: Binding failed for Socket %d (timeout after %dms)\n",
                sockfd, elapsedTimeMs);
        errno = ETIMEDOUT;
        result = -1;
    }

    //  Release Socket access
    pthread_mutex_unlock(&SocketArray[sockfd].socket_mutex);

    return result;
}

// funtion definition for k_sendto
static int find_available_buffer_slot(int sockfd, ktp_socket_t *sockets);
static void prepare_send_buffer(int sockfd, int position, const void *data, size_t length, ktp_socket_t *sockets);
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
    size_t bytes_to_transfer;
    int buffer_position;
    ktp_socket_t *ktp_sockets;
    const struct sockaddr_in *target_address;

    // Retrieve socket array from shared memory
    ktp_sockets = get_KTPsock_arr();
    if (ktp_sockets == NULL)
    {
        errno = EINVAL;
        return -1;
    }

    // Check socket descriptor validity
    if ((sockfd < 0) ||
        (sockfd >= KTP_MAX_SOCKETS) ||
        (!ktp_sockets[sockfd].is_allocated))
    {
        errno = EBADF;
        return -1;
    }

    // Acquire exclusive access to socket
    if (pthread_mutex_lock(&ktp_sockets[sockfd].socket_mutex) != 0)
    {
        errno = EAGAIN;
        return -1;
    }

    // Require socket to be bound before sending
    if (!ktp_sockets[sockfd].is_bound)
    {
        pthread_mutex_unlock(&ktp_sockets[sockfd].socket_mutex);
        errno = E_KTP_NOT_BOUND;
        return -1;
    }

    // Destination address validation
    target_address = (const struct sockaddr_in *)dest_addr;
    if ((target_address->sin_addr.s_addr != ktp_sockets[sockfd].dst_addr.sin_addr.s_addr) ||
        (target_address->sin_port != ktp_sockets[sockfd].dst_addr.sin_port))
    {
        pthread_mutex_unlock(&ktp_sockets[sockfd].socket_mutex);
        errno = E_KTP_NOT_BOUND;
        return -1;
    }

    // Locate available buffer slot
    buffer_position = find_available_buffer_slot(sockfd, ktp_sockets);
    if (buffer_position < 0)
    {
        pthread_mutex_unlock(&ktp_sockets[sockfd].socket_mutex);
        errno = E_KTP_NO_SPACE;
        return -1;
    }

    // Calculate data size to transfer (capped by buffer size)
    bytes_to_transfer = len < KTP_MSG_SIZE ? len : KTP_MSG_SIZE;

    // Prepare and copy data to transmission buffer
    prepare_send_buffer(sockfd, buffer_position, buf, bytes_to_transfer, ktp_sockets);

    // Release mutex before returning
    pthread_mutex_unlock(&ktp_sockets[sockfd].socket_mutex);

    // Return actual bytes queued
    return bytes_to_transfer;
}

/*
 * Helper function to find available send buffer slot
 * Returns buffer index if available, -1 if buffer is full
 */
static int find_available_buffer_slot(int sockfd, ktp_socket_t *sockets)
{
    int window_base = sockets[sockfd].swnd.base;
    int pending_packets = sockets[sockfd].swnd.num_unacked;
    int current_pos;

    // Search through buffer for available slot
    for (int offset = 0; offset < KTP_SEND_BUFFER_SIZE; offset++)
    {
        current_pos = (window_base + pending_packets + offset) % KTP_SEND_BUFFER_SIZE;

        // Found empty slot
        if (sockets[sockfd].send_buffer_occ[current_pos] == 0)
        {
            return current_pos;
        }
    }

    // No available slots found
    return -1;
}

/*
 * Helper function to prepare send buffer and mark as occupied
 */
static void prepare_send_buffer(int sockfd, int position, const void *data,
                                size_t length, ktp_socket_t *sockets)
{
    // Clear buffer slot before use
    memset(sockets[sockfd].send_buffer[position], 0, KTP_MSG_SIZE);

    // Copy user data to buffer
    memcpy(sockets[sockfd].send_buffer[position], data, length);

    // Mark buffer slot as occupied
    sockets[sockfd].send_buffer_occ[position] = 1;
}

// Forward declarations of helper functions
static inline size_t compute_data_length(const char *buffer, size_t max_size);
static inline void update_receive_state(ktp_socket_t *sock, int pos);

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
    // Early validation of socket descriptor range
    if (sockfd < 0 || sockfd >= KTP_MAX_SOCKETS)
    {
        errno = EBADF;
        return -1;
    }

    // Access shared transport memory region
    ktp_socket_t *transport = get_KTPsock_arr();
    if (transport == NULL)
    {
        errno = EINVAL;
        return -1;
    }

    // Further socket validation
    if (!transport[sockfd].is_allocated)
    {
        errno = EBADF;
        return -1;
    }

    // Critical section - acquire resource lock
    int lock_result = pthread_mutex_lock(&transport[sockfd].socket_mutex);
    if (lock_result != 0)
    {
        errno = EAGAIN;
        return -1;
    }

    // Check data availability
    ktp_recv_window_t *rx_window = &transport[sockfd].rwnd;
    if (rx_window->buffer_occupied == 0)
    {
        pthread_mutex_unlock(&transport[sockfd].socket_mutex);
        errno = E_KTP_NO_MESSAGE;
        return -1;
    }

    // Locate data position
    int buffer_index = rx_window->buffer_read_pos;
    char *data_source = transport[sockfd].recv_buffer[buffer_index];

    // Determine amount to transfer
    size_t available = compute_data_length(data_source, KTP_MSG_SIZE);
    size_t transfer_size = (available < len) ? available : len;

    // Transfer data to user buffer
    if (transfer_size > 0)
    {
        memcpy(buf, data_source, transfer_size);
    }

    // Reset used buffer space
    memset(data_source, 0, KTP_MSG_SIZE);

    // Update internal state trackers
    update_receive_state(&transport[sockfd], buffer_index);

    // End of critical section
    pthread_mutex_unlock(&transport[sockfd].socket_mutex);

    return transfer_size;
}

/**
 * Calculate effective data length in buffer
 */
static inline size_t compute_data_length(const char *buffer, size_t max_size)
{
    // Use string length as message length indicator
    size_t actual_length = 0;
    while (actual_length < max_size && buffer[actual_length] != '\0')
    {
        actual_length++;
    }
    return actual_length;
}

/**
 * Update socket receive window state after successful read
 */
static inline void update_receive_state(ktp_socket_t *sock, int pos)
{
    // Move read position to next slot
    sock->rwnd.buffer_read_pos = (pos + 1) % KTP_RECV_BUFFER_SIZE;

    // Reduce buffer utilization counter
    sock->rwnd.buffer_occupied--;

    // Increase available window size for flow control
    sock->rwnd.size++;
}

/**
 * Helper function to clear send buffers for a KTP socket
 */
static void clear_send_buffers(ktp_socket_t *connection)
{
    int i = KTP_SEND_BUFFER_SIZE;
    while (i-- > 0)
    {
        memset(connection->send_buffer[i], 0, KTP_MSG_SIZE);
        connection->send_buffer_occ[i] = 0;
    }
}

/**
 * Helper function to clear receive buffers for a KTP socket
 */
static void clear_receive_buffers(ktp_socket_t *connection)
{
    for (int idx = 0; idx < KTP_RECV_BUFFER_SIZE; ++idx)
    {
        memset(connection->recv_buffer[idx], 0, KTP_MSG_SIZE);
    }
}

/**
 * Helper function to reset state tracking for a KTP socket
 */
static void reset_state_tracking(ktp_socket_t *connection)
{
    // Reset reception tracking
    memset(connection->rwnd.received_msgs, 0,
           sizeof(connection->rwnd.received_msgs));

    // Reset window structures with single operations
    memset(&connection->swnd, 0, sizeof(connection->swnd));
    memset(&connection->rwnd, 0, sizeof(connection->rwnd));
}

/**
 * Releases a KTP socket and cleans up resources
 *
 * @param sockfd    Socket identifier to release
 * @return          0 when successful, -1 on error with errno set
 */
int k_close(int sockfd)
{
    // Access socket registry
    ktp_socket_t *registry = get_KTPsock_arr();
    if (registry == NULL)
    {
        errno = EINVAL;
        return -1;
    }

    // Validate socket identifier
    if ((sockfd < 0) || (sockfd >= KTP_MAX_SOCKETS))
    {
        errno = EBADF; // Invalid descriptor
        return -1;
    }

    // Verify socket exists
    ktp_socket_t *connection = &registry[sockfd];
    if (!connection->is_allocated)
    {
        errno = EBADF; // Not an active socket
        return -1;
    }

    // Acquire exclusive access
    if (pthread_mutex_lock(&connection->socket_mutex) != 0)
    {
        errno = EAGAIN;
        return -1;
    }

    // Deallocate and reset basic state
    connection->is_allocated = 0;
    connection->pid = 0;
    connection->is_bound = 0;
    connection->bind_requested = 0;

    // Clear all buffers and reset state
    clear_send_buffers(connection);
    clear_receive_buffers(connection);
    reset_state_tracking(connection);

    // Release lock and report success
    pthread_mutex_unlock(&connection->socket_mutex);
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
    if (p <= 0.0f || p >= 1.0f)
        return 0;

    int random_value = rand() % 10000;

    int threshold = (int)(p * 10000);

    // Return drop decision (1=drop, 0=keep)
    return (random_value < threshold);
}