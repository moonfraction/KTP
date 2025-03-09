/**
 * KTP Protocol Management Daemon
 *
 * Central controller process for KTP networking protocol
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <errno.h>
#include "ksocket.h"

/* Terminal color codes for log output */
#define BOLD_CYAN "\033[1;36m"
#define COLOR_BLUE "\033[0;36m"
#define COLOR_RESET "\033[0m"
#define COLOR_MAGENTA "\033[0;35m"
#define BOLD_RED "\033[1;31m"
#define COLOR_RED "\033[0;31m"
#define COLOR_GREEN "\033[0;32m"
#define COLOR_YELLOW "\033[0;33m"

/* Global state variables */
static int isRunning = 1;               /* Flag controlling thread execution */
static int shmHandle = -1;              /* Shared memory ID */
static ktp_socket_t *ktpSockets = NULL; /* Socket array in shared memory */

/**
 * Signal handler for graceful shutdown
 *
 * @param sig Signal number received
 */
void handle_signal(int sig)
{
    printf(COLOR_MAGENTA "KTP Manager: Signal %d received, initiating shutdown sequence...\n", sig);
    isRunning = 0;
}

/**
 * Establish shared memory region for KTP protocol communication
 *
 * @return Status code: 0=success, -1=failure
 */
int init_shared_memory(void)
{
    int status = 0;
    const char *KEY_PATH = "/";
    const int KEY_ID = 'A';

    // Generate unique system key for memory segment
    key_t memoryKey = ftok(KEY_PATH, KEY_ID);
    if (memoryKey == -1)
    {
        fprintf(stderr, COLOR_MAGENTA "KTP Manager: Unable to generate memory key\n");
        return -1;
    }

    // Allocate shared memory block
    const size_t requiredBytes = sizeof(ktp_socket_t) * KTP_MAX_SOCKETS;
    int memoryId = shmget(memoryKey, requiredBytes, 0666 | IPC_CREAT);
    if (memoryId < 0)
    {
        fprintf(stderr, COLOR_MAGENTA "KTP Manager: Memory segment creation failed\n");
        return -1;
    }
    shmHandle = memoryId;

    // Connect to allocated memory
    void *memoryRegion = shmat(memoryId, NULL, 0);
    if (memoryRegion == (void *)-1)
    {
        fprintf(stderr, COLOR_MAGENTA "KTP Manager: Cannot attach to memory segment\n");
        return -1;
    }
    ktpSockets = (ktp_socket_t *)memoryRegion;

    // Configure individual socket slots
    for (int socketIndex = 0; socketIndex < KTP_MAX_SOCKETS; socketIndex++)
    {
        // Clear memory slot
        ktp_socket_t *currentSocket = &ktpSockets[socketIndex];
        memset(currentSocket, 0, sizeof(ktp_socket_t));

        // Set up underlying transport socket
        int transportDescriptor = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (transportDescriptor < 0)
        {
            printf(COLOR_MAGENTA "KTP Manager: Warning - Socket %d initialization failed\n", socketIndex);
            status = -1;
            continue;
        }

        // Configure slot properties
        currentSocket->udp_sockfd = transportDescriptor;
        currentSocket->is_allocated = 0;

        // Initialize synchronization primitives
        pthread_mutexattr_t mutexConfig;
        pthread_mutexattr_init(&mutexConfig);
        pthread_mutexattr_setpshared(&mutexConfig, PTHREAD_PROCESS_SHARED);

        if (pthread_mutex_init(&currentSocket->socket_mutex, &mutexConfig) != 0)
        {
            printf(COLOR_MAGENTA "KTP Manager: Warning - Mutex initialization failed for socket %d\n", socketIndex);
            close(transportDescriptor);
            status = -1;
        }

        pthread_mutexattr_destroy(&mutexConfig);

        printf(COLOR_MAGENTA "KTP Manager: Initialized socket %d (fd=%d)\n",
               socketIndex, transportDescriptor);
    }

    if (status == 0)
    {
        printf(COLOR_MAGENTA "KTP Manager: Socket memory region ready with %d slots\n", KTP_MAX_SOCKETS);
    }

    return status;
}

/**
 * Performs resource deallocation
 *
 * This function ensures all allocated system resources are properly
 * released, avoiding memory leaks and abandoned IPC segments.
 */
void cleanup(void)
{
    int cleanup_status = 0;

    // Log beginning of cleanup process
    fprintf(stdout, COLOR_BLUE "KTP Service: Beginning resource cleanup\n");

    // Handle socket memory region
    if (ktpSockets)
    {
        // Only attempt detachment if pointer is valid
        if (ktpSockets != (void *)-1)
        {
            // Release connection to shared memory
            int result = shmdt(ktpSockets);
            if (result != 0)
            {
                fprintf(stderr, COLOR_RED "KTP Service: Error %d detaching from memory segment\n", errno);
                cleanup_status = -1;
            }
            else
            {
                fprintf(stdout, COLOR_BLUE "KTP Service: Memory segment detached\n");
            }
        }
        else
        {
            fprintf(stderr, COLOR_RED "KTP Service: Invalid memory segment pointer detected\n");
            cleanup_status = -1;
        }

        // Reset pointer to avoid double-free
        ktpSockets = NULL;
    }

    // Remove shared memory segment
    if (shmHandle >= 0)
    {
        // Request removal of shared memory from system
        int result = shmctl(shmHandle, IPC_RMID, NULL);
        if (result != 0)
        {
            fprintf(stderr, COLOR_RED "KTP Service: Error %d removing shared memory segment\n", errno);
            cleanup_status = -1;
        }
        else
        {
            fprintf(stdout, COLOR_BLUE "KTP Service: Shared memory segment released\n");
        }

        // Mark handle as invalid
        shmHandle = -1;
    }

    // Report final cleanup status
    if (cleanup_status == 0)
    {
        fprintf(stdout, COLOR_GREEN "KTP Service: Resource cleanup completed successfully\n");
    }
    else
    {
        fprintf(stderr, COLOR_YELLOW "KTP Service: Resource cleanup completed with warnings\n");
    }
}

// funtion defintions
static void process_pending_bindings(void);
static int prepare_descriptor_set(fd_set *descriptorSet);
static int try_lock_active_socket(int socketId);
static int handle_incoming_packet(int socketId, unsigned int *packetCounter,
                                  unsigned int *lossCounter, int *notificationArray);
static void process_data_packet(int socketId, ktp_message_t *message, struct sockaddr_in *sender);
static void process_ack_packet(int socketId, ktp_message_t *message);
static void process_acknowledged_packets(int socketId, int ackCount);
static void store_data_packet(int socketId, ktp_message_t *message);
static void update_receive_window_state(int socketId);
static void send_acknowledgment(int socketId);
static void send_buffer_state_updates(int *notificationArray);

/**
 * Receiver thread *
 * Network packet reception and processing thread
 *
 * Handles incoming network traffic and maintains protocol state
 *
 * @param threadArgs Thread parameters (unused)
 * @return Always returns NULL
 */
void *R_thread(void *threadArgs)
{
    // Initialize statistics counters
    unsigned int totalPackets = 0;
    unsigned int lostPackets = 0;

    // Prepare socket monitoring structures
    fd_set activeDescriptors;
    struct timeval pollTimeout;

    // Setup buffer notification tracking array
    int pendingBufferNotifications[KTP_MAX_SOCKETS];
    memset(pendingBufferNotifications, 0, sizeof(pendingBufferNotifications));

    fprintf(stdout, BOLD_CYAN "KTP: R_thread initialized and running\n" COLOR_RESET);

    // Main processing loop
    while (isRunning)
    {
        // Handle socket binding operations
        process_pending_bindings();

        // Prepare monitoring set for active sockets
        int highestDescriptor = prepare_descriptor_set(&activeDescriptors);

        // Skip polling if no active sockets exist
        if (highestDescriptor < 0)
        {
            usleep(150000); // 150ms pause before retry
            continue;
        }

        // Configure polling timeout
        pollTimeout.tv_sec = 0;
        pollTimeout.tv_usec = 750000; // 750ms timeout

        // Monitor sockets for activity
        int readyCount = select(highestDescriptor + 1, &activeDescriptors, NULL, NULL, &pollTimeout);

        // Handle select errors
        if (readyCount < 0)
        {
            if (isRunning)
            {
                fprintf(stderr, COLOR_RED "KTP: Socket monitoring failed: %s\n" COLOR_RESET, strerror(errno));
            }
            continue;
        }

        // Process sockets with pending data
        for (int socketIndex = 0; socketIndex < KTP_MAX_SOCKETS; socketIndex++)
        {
            // Skip locked or inactive sockets
            if (!try_lock_active_socket(socketIndex))
                continue;

            int descriptor = ktpSockets[socketIndex].udp_sockfd;

            // Check if this socket has data available
            if (FD_ISSET(descriptor, &activeDescriptors))
            {
                // Process incoming packet
                if (handle_incoming_packet(socketIndex, &totalPackets, &lostPackets,
                                           pendingBufferNotifications) != 0)
                {
                    // Error handling if needed
                }
            }

            pthread_mutex_unlock(&ktpSockets[socketIndex].socket_mutex);
        }

        // Handle buffer state notifications
        send_buffer_state_updates(pendingBufferNotifications);
    }

    // Output final statistics before termination
    if (totalPackets > 0)
    {
        fprintf(stdout, COLOR_YELLOW "KTP: Traffic summary - %u packets received, "
                                     "%u lost (%.1f%% loss rate)\n" COLOR_RESET,
                totalPackets, lostPackets, (lostPackets * 100.0) / totalPackets);
    }

    fprintf(stdout, BOLD_CYAN "KTP: R_thread terminated\n" COLOR_RESET);
    return NULL;
}

/**
 * Process all pending socket binding requests
 */
static void process_pending_bindings(void)
{
    for (int socketId = 0; socketId < KTP_MAX_SOCKETS; socketId++)
    {
        if (pthread_mutex_trylock(&ktpSockets[socketId].socket_mutex) != 0)
            continue;

        // Check if this socket needs binding
        int bindingNeeded = ktpSockets[socketId].is_allocated &&
                            ktpSockets[socketId].bind_requested &&
                            !ktpSockets[socketId].is_bound;

        if (bindingNeeded)
        {
            fprintf(stdout, COLOR_GREEN "KTP: Processing bind request for socket %d\n" COLOR_RESET, socketId);

            // Create fresh UDP socket
            close(ktpSockets[socketId].udp_sockfd);
            int newSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            ktpSockets[socketId].udp_sockfd = newSocket;

            // Attempt binding operation
            if (bind(newSocket, (struct sockaddr *)&ktpSockets[socketId].src_addr,
                     sizeof(struct sockaddr_in)) == 0)
            {
                // Binding succeeded
                ktpSockets[socketId].is_bound = 1;
                ktpSockets[socketId].bind_requested = 0;
                fprintf(stdout, COLOR_GREEN "KTP: Socket %d successfully bound\n" COLOR_RESET, socketId);
            }
            else
            {
                fprintf(stderr, COLOR_RED "KTP: Failed to bind socket %d: %s\n" COLOR_RESET,
                        socketId, strerror(errno));
            }
        }

        pthread_mutex_unlock(&ktpSockets[socketId].socket_mutex);
    }
}

/**
 * Prepare the file descriptor set for select()
 *
 * @param descriptorSet Pointer to fd_set to populate
 * @return Highest file descriptor value, or -1 if no active sockets
 */
static int prepare_descriptor_set(fd_set *descriptorSet)
{
    int maxDescriptor = -1;
    FD_ZERO(descriptorSet);

    for (int socketId = 0; socketId < KTP_MAX_SOCKETS; socketId++)
    {
        if (pthread_mutex_trylock(&ktpSockets[socketId].socket_mutex) != 0)
            continue;

        int socketActive = ktpSockets[socketId].is_allocated &&
                           ktpSockets[socketId].is_bound &&
                           ktpSockets[socketId].udp_sockfd >= 0;

        if (socketActive)
        {
            int descriptor = ktpSockets[socketId].udp_sockfd;

            // Validate socket before using
            int errorState = 0;
            socklen_t errorLen = sizeof(errorState);
            if (getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &errorState, &errorLen) == 0 &&
                errorState == 0)
            {
                // Socket is valid
                FD_SET(descriptor, descriptorSet);
                maxDescriptor = (descriptor > maxDescriptor) ? descriptor : maxDescriptor;
            }
            else
            {
                // Invalid socket - mark for cleanup
                fprintf(stdout, COLOR_YELLOW "KTP: Invalid socket %d detected, marking for cleanup\n" COLOR_RESET,
                        socketId);
                ktpSockets[socketId].is_allocated = 0;
                ktpSockets[socketId].udp_sockfd = -1;
            }
        }

        pthread_mutex_unlock(&ktpSockets[socketId].socket_mutex);
    }

    return maxDescriptor;
}

/**
 * Attempt to lock a socket if it's active
 *
 * @param socketId Socket index to check
 * @return 1 if socket was locked and is active, 0 otherwise
 */
static int try_lock_active_socket(int socketId)
{
    if (pthread_mutex_trylock(&ktpSockets[socketId].socket_mutex) != 0)
        return 0;

    if (!ktpSockets[socketId].is_allocated || !ktpSockets[socketId].is_bound)
    {
        pthread_mutex_unlock(&ktpSockets[socketId].socket_mutex);
        return 0;
    }

    return 1;
}

/**
 * Process an incoming network packet
 *
 * @param socketId Socket index
 * @param packetCounter Pointer to packet counter
 * @param lossCounter Pointer to loss counter
 * @param notificationArray Buffer notification array
 * @return 0 on success, non-zero on error
 */
static int handle_incoming_packet(int socketId, unsigned int *packetCounter,
                                  unsigned int *lossCounter, int *notificationArray)
{
    ktp_message_t incomingMsg;
    struct sockaddr_in senderAddr;
    socklen_t addrLen = sizeof(senderAddr);

    // Receive the data
    ssize_t bytesRead = recvfrom(ktpSockets[socketId].udp_sockfd, &incomingMsg,
                                 sizeof(incomingMsg), 0,
                                 (struct sockaddr *)&senderAddr, &addrLen);

    // Update statistics
    (*packetCounter)++;

    // Check for simulated packet loss
    if (dropMessage(KTP_PACKET_LOSS_PROB))
    {
        fprintf(stdout, COLOR_RED "KTP: Simulated packet loss on socket %d\n" COLOR_RESET, socketId);
        (*lossCounter)++;
        return 0;
    }

    // Handle receive errors
    if (bytesRead <= 0)
        return -1;

    // Process by message type
    switch (incomingMsg.header.type)
    {
    case KTP_TYPE_DATA:
        process_data_packet(socketId, &incomingMsg, &senderAddr);
        // Reset buffer notification counter
        notificationArray[socketId] = 0;
        break;

    case KTP_TYPE_ACK:
        process_ack_packet(socketId, &incomingMsg);
        break;

    default:
        fprintf(stderr, COLOR_RED "KTP: Unknown packet type %d received\n" COLOR_RESET,
                incomingMsg.header.type);
        break;
    }

    return 0;
}

/**
 * Process DATA type packet
 */
static void process_data_packet(int socketId, ktp_message_t *message, struct sockaddr_in *sender)
{
    uint8_t sequenceNum = message->header.seq_num;
    uint8_t expectedSeq = ktpSockets[socketId].rwnd.expected_seq_num;

    fprintf(stdout, COLOR_GREEN "KTP: Socket %d received DATA packet sequence=%d\n" COLOR_RESET,
            socketId, sequenceNum);

    // Check for duplicate packet
    int isDuplicate = 0;
    for (int i = 0; i < KTP_RECV_BUFFER_SIZE; i++)
    {
        if (ktpSockets[socketId].rwnd.received_msgs[i] == sequenceNum)
        {
            isDuplicate = 1;
            break;
        }
    }

    // Calculate window boundaries
    int inWindow = 0;
    uint8_t windowEnd = (expectedSeq + ktpSockets[socketId].rwnd.size - 1) % 256;

    // Handle window wrap-around
    if (expectedSeq <= windowEnd)
    {
        inWindow = (sequenceNum >= expectedSeq && sequenceNum <= windowEnd);
    }
    else
    {
        inWindow = (sequenceNum >= expectedSeq || sequenceNum <= windowEnd);
    }

    // Handle packet based on duplicate status and window position
    if (isDuplicate)
    {
        // Send duplicate ACK
        send_acknowledgment(socketId);
    }
    else if (inWindow)
    {
        // New in-window packet
        store_data_packet(socketId, message);
    }
    else
    {
        fprintf(stdout, COLOR_RED "KTP: Socket %d discarded out-of-window packet seq=%d\n" COLOR_RESET,
                socketId, sequenceNum);
    }
}

/**
 * Process ACK type packet
 */
static void process_ack_packet(int socketId, ktp_message_t *message)
{
    uint8_t lastAcknowledged = message->header.last_ack;
    uint8_t advertisedWindow = message->header.rwnd;

    fprintf(stdout, COLOR_GREEN "KTP: Socket %d received ACK for seq=%d window=%d\n" COLOR_RESET,
            socketId, lastAcknowledged, advertisedWindow);

    // Update send window size based on receiver's advertised window
    ktpSockets[socketId].swnd.size = advertisedWindow;

    // Count acknowledged packets
    int acknowledgedCount = 0;
    int foundAck = 0;

    for (int i = 0; i < ktpSockets[socketId].swnd.num_unacked; i++)
    {
        int windowPos = (ktpSockets[socketId].swnd.base + i) % KTP_MAX_WINDOW_SIZE;
        uint8_t seqNum = ktpSockets[socketId].swnd.seq_nums[windowPos];

        acknowledgedCount++;

        if (seqNum == lastAcknowledged)
        {
            foundAck = 1;
            break;
        }
    }

    // Handle duplicate or spurious ACK
    if (!foundAck)
    {
        fprintf(stdout, COLOR_YELLOW "KTP: Socket %d received duplicate ACK %d\n" COLOR_RESET,
                socketId, lastAcknowledged);
        return;
    }

    // Process valid ACK
    process_acknowledged_packets(socketId, acknowledgedCount);
}

/**
 * Process acknowledged packets and update window
 */
static void process_acknowledged_packets(int socketId, int ackCount)
{
    fprintf(stdout, COLOR_GREEN "KTP: Socket %d processing %d acknowledged packets\n" COLOR_RESET,
            socketId, ackCount);

    // Clear acknowledged packets from buffer
    for (int i = 0; i < ackCount; i++)
    {
        int bufferIndex = (ktpSockets[socketId].swnd.base + i) % KTP_SEND_BUFFER_SIZE;
        memset(ktpSockets[socketId].send_buffer[bufferIndex], 0, KTP_MSG_SIZE);
        ktpSockets[socketId].send_buffer_occ[bufferIndex] = 0;
    }

    // Update window state
    ktpSockets[socketId].swnd.base = (ktpSockets[socketId].swnd.base + ackCount) % KTP_MAX_WINDOW_SIZE;
    ktpSockets[socketId].swnd.num_unacked -= ackCount;
}

/**
 * Store data packet in receive buffer
 */
static void store_data_packet(int socketId, ktp_message_t *message)
{
    uint8_t sequenceNum = message->header.seq_num;
    uint8_t expectedSeq = ktpSockets[socketId].rwnd.expected_seq_num;

    // Check buffer capacity
    if (ktpSockets[socketId].rwnd.buffer_occupied >= KTP_RECV_BUFFER_SIZE)
    {
        // Buffer is full
        ktpSockets[socketId].rwnd.nospace_flag = 1;
        ktpSockets[socketId].rwnd.size = 0;

        fprintf(stdout, COLOR_YELLOW "KTP: Socket %d buffer full, packet %d dropped\n" COLOR_RESET,
                socketId, sequenceNum);
        return;
    }

    // Store packet in receive buffer
    int writePos = ktpSockets[socketId].rwnd.buffer_write_pos;
    int offset = ((sequenceNum - expectedSeq + 256) % 256) % KTP_RECV_BUFFER_SIZE;
    int bufferPos = (writePos + offset) % KTP_RECV_BUFFER_SIZE;

    // Copy data to buffer
    memcpy(ktpSockets[socketId].recv_buffer[bufferPos], message->data, KTP_MSG_SIZE);
    ktpSockets[socketId].rwnd.received_msgs[bufferPos] = sequenceNum;

    // Process in-order packets
    update_receive_window_state(socketId);

    // Update acknowledgment information
    ktpSockets[socketId].rwnd.last_ack_sent = (ktpSockets[socketId].rwnd.expected_seq_num - 1 + 256) % 256;

    // Send acknowledgment
    send_acknowledgment(socketId);

    // Check if buffer is now full
    if (ktpSockets[socketId].rwnd.buffer_occupied >= KTP_RECV_BUFFER_SIZE)
    {
        ktpSockets[socketId].rwnd.nospace_flag = 1;
        ktpSockets[socketId].rwnd.size = 0;
    }
}

/**
 * Update receive window state based on received packets
 */
static void update_receive_window_state(int socketId)
{
    // Process consecutive in-order packets
    while (ktpSockets[socketId].rwnd.received_msgs[ktpSockets[socketId].rwnd.buffer_write_pos] ==
           ktpSockets[socketId].rwnd.expected_seq_num)
    {
        // Update state for this in-order packet
        ktpSockets[socketId].rwnd.expected_seq_num =
            (ktpSockets[socketId].rwnd.expected_seq_num + 1) % 256;

        ktpSockets[socketId].rwnd.buffer_write_pos =
            (ktpSockets[socketId].rwnd.buffer_write_pos + 1) % KTP_RECV_BUFFER_SIZE;

        ktpSockets[socketId].rwnd.buffer_occupied++;
        ktpSockets[socketId].rwnd.size--;
    }
}

/**
 * Send acknowledgment packet
 */
static void send_acknowledgment(int socketId)
{
    ktp_message_t ackMsg;
    memset(&ackMsg, 0, sizeof(ackMsg));

    ackMsg.header.type = KTP_TYPE_ACK;
    ackMsg.header.last_ack = ktpSockets[socketId].rwnd.last_ack_sent;
    ackMsg.header.rwnd = ktpSockets[socketId].rwnd.size;

    fprintf(stdout, COLOR_GREEN "KTP: Socket %d sending ACK seq=%d window=%d\n" COLOR_RESET,
            socketId, ackMsg.header.last_ack, ackMsg.header.rwnd);

    sendto(ktpSockets[socketId].udp_sockfd, &ackMsg, sizeof(ackMsg.header), 0,
           (struct sockaddr *)&ktpSockets[socketId].dst_addr, sizeof(struct sockaddr_in));
}

/**
 * Send buffer state updates for sockets that need them
 */
static void send_buffer_state_updates(int *notificationArray)
{
    for (int socketId = 0; socketId < KTP_MAX_SOCKETS; socketId++)
    {
        if (pthread_mutex_trylock(&ktpSockets[socketId].socket_mutex) != 0)
            continue;

        if (ktpSockets[socketId].is_allocated && ktpSockets[socketId].is_bound)
        {
            // Check if buffer was previously full but now has space
            int bufferFreed = ktpSockets[socketId].rwnd.nospace_flag &&
                              ktpSockets[socketId].rwnd.buffer_occupied < KTP_RECV_BUFFER_SIZE;

            if (bufferFreed)
            {
                // Buffer now has space, send update notifications
                ktpSockets[socketId].rwnd.nospace_flag = 0;
                notificationArray[socketId] = 10; // Schedule 10 notification messages

                fprintf(stdout, COLOR_GREEN "KTP: Socket %d buffer now available, scheduling updates\n" COLOR_RESET,
                        socketId);
            }

            // Send any scheduled buffer notifications
            if (notificationArray[socketId] > 0)
            {
                ktp_message_t ackMsg;
                memset(&ackMsg, 0, sizeof(ackMsg));

                ackMsg.header.type = KTP_TYPE_ACK;
                ackMsg.header.last_ack = ktpSockets[socketId].rwnd.last_ack_sent;
                ackMsg.header.rwnd = ktpSockets[socketId].rwnd.size;

                fprintf(stdout, COLOR_GREEN "KTP: Socket %d buffer notification %d/10: ack=%d window=%d\n" COLOR_RESET, socketId, 11 - notificationArray[socketId],
                        ackMsg.header.last_ack, ackMsg.header.rwnd);

                sendto(ktpSockets[socketId].udp_sockfd, &ackMsg, sizeof(ackMsg.header), 0,
                       (struct sockaddr *)&ktpSockets[socketId].dst_addr, sizeof(struct sockaddr_in));

                notificationArray[socketId]--;
            }
        }

        pthread_mutex_unlock(&ktpSockets[socketId].socket_mutex);
    }
}

// functions in S_thread
/**
 * Process packet timeouts for Socket
 * @returns Number of packets retransmitted
 */
static int handle_Socket_timeouts(int SocketId, struct timeval *now)
{
    int retransmittedCount = 0;
    int hasTimedOutPackets = 0;
    ktp_socket_t *Socket = &ktpSockets[SocketId];

    // First detect if any packet has timed out
    for (int packetIdx = 0; packetIdx < Socket->swnd.num_unacked; packetIdx++)
    {
        int windowPos = (Socket->swnd.base + packetIdx) % KTP_MAX_WINDOW_SIZE;

        // Calculate elapsed time
        double elapsedSecs = (now->tv_sec - Socket->swnd.send_times[windowPos].tv_sec) +
                             (now->tv_usec - Socket->swnd.send_times[windowPos].tv_usec) / 1000000.0;

        if (elapsedSecs >= KTP_TIMEOUT_SEC)
        {
            hasTimedOutPackets = 1;
            break;
        }
    }

    // If timeout detected, resend entire window
    if (hasTimedOutPackets && Socket->swnd.num_unacked > 0)
    {
        fprintf(stdout, COLOR_RED "KTP: Socket %d timeout detected - "
                                  "resending %d packets\n" COLOR_RESET,
                SocketId, Socket->swnd.num_unacked);

        // Go through all unacknowledged packets
        for (int packetIdx = 0; packetIdx < Socket->swnd.num_unacked; packetIdx++)
        {
            // Calculate relevant buffer positions
            int windowPos = (Socket->swnd.base + packetIdx) % KTP_MAX_WINDOW_SIZE;
            int bufferPos = (Socket->swnd.base + packetIdx) % KTP_SEND_BUFFER_SIZE;
            uint8_t seqNumber = Socket->swnd.seq_nums[windowPos];

            // Prepare retransmission packet
            ktp_message_t pkt;
            memset(&pkt, 0, sizeof(pkt));

            pkt.header.type = KTP_TYPE_DATA;
            pkt.header.seq_num = seqNumber;
            pkt.header.rwnd = Socket->rwnd.size;
            pkt.header.last_ack = (Socket->rwnd.expected_seq_num - 1) % 256;

            // Copy payload data
            memcpy(pkt.data, Socket->send_buffer[bufferPos], KTP_MSG_SIZE);

            // Transmit packet
            if (sendto(Socket->udp_sockfd, &pkt, sizeof(pkt), 0,
                       (struct sockaddr *)&Socket->dst_addr,
                       sizeof(struct sockaddr_in)) > 0)
            {
                retransmittedCount++;

                // Update timestamp to prevent immediate retransmission
                gettimeofday(&Socket->swnd.send_times[windowPos], NULL);
            }
        }
    }

    return retransmittedCount;
}

/**
 * Transmit new packets for Socket within window constraints
 * @returns Number of packets sent
 */
static int transmit_new_packets(int SocketId, unsigned int *stats)
{
    int packetsSent = 0;
    ktp_socket_t *Socket = &ktpSockets[SocketId];

    // Try to send as many packets as window allows
    while (Socket->swnd.num_unacked < Socket->swnd.size)
    {
        // Find next packet to send
        int nextPacketPos = (Socket->swnd.base + Socket->swnd.num_unacked) % KTP_SEND_BUFFER_SIZE;

        // Check if buffer slot contains data ready to send
        if (Socket->send_buffer_occ[nextPacketPos] == 0)
        {
            break; // No more data waiting to be sent
        }

        // Prepare new data packet
        ktp_message_t pkt;
        memset(&pkt, 0, sizeof(pkt));

        // Configure packet headers
        pkt.header.type = KTP_TYPE_DATA;
        pkt.header.seq_num = Socket->swnd.next_seq_num;
        pkt.header.rwnd = Socket->rwnd.size;
        pkt.header.last_ack = (Socket->rwnd.expected_seq_num - 1) % 256;

        // Copy payload data
        memcpy(pkt.data, Socket->send_buffer[nextPacketPos], KTP_MSG_SIZE);

        // Update window tracking
        int windowPos = (Socket->swnd.base + Socket->swnd.num_unacked) % KTP_MAX_WINDOW_SIZE;
        Socket->swnd.seq_nums[windowPos] = pkt.header.seq_num;

        // Record transmission time
        gettimeofday(&Socket->swnd.send_times[windowPos], NULL);

        // Transmit packet
        if (sendto(Socket->udp_sockfd, &pkt, sizeof(pkt), 0,
                   (struct sockaddr *)&Socket->dst_addr,
                   sizeof(struct sockaddr_in)) > 0)
        {
            packetsSent++;

            fprintf(stdout, COLOR_GREEN "KTP: Socket %d sent packet seq=%d\n" COLOR_RESET,
                    SocketId, pkt.header.seq_num);

            // Update window state
            Socket->swnd.next_seq_num = (Socket->swnd.next_seq_num + 1) % 256;
            Socket->swnd.num_unacked++;

            // Update statistics
            stats[SocketId]++;
        }
        else
        {
            fprintf(stderr, COLOR_RED "KTP: Socket %d send error: %s\n" COLOR_RESET,
                    SocketId, strerror(errno));
            break; // Stop on error
        }
    }

    return packetsSent;
}

/**
 * Check if flow control is limiting transmission on an Socket
 * @return 1 if window is full, 0 otherwise
 */
static int is_flow_controlled(int SocketId)
{
    return ktpSockets[SocketId].swnd.num_unacked >= ktpSockets[SocketId].swnd.size;
}

/**
 * Sender thread *
 * Data transmission control thread - Handles reliable packet delivery
 *
 * @param threadContext Thread context (unused)
 * @return Always NULL on thread exit
 */
void *S_thread(void *threadContext)
{
    fprintf(stdout, COLOR_YELLOW "KTP: S_thread activated\n" COLOR_RESET);

    // Operational statistics tracking
    unsigned int txPackets[KTP_MAX_SOCKETS] = {0};
    unsigned int retransmissions[KTP_MAX_SOCKETS] = {0};
    unsigned int flowControlHits[KTP_MAX_SOCKETS] = {0};

    // Main controller loop
    while (isRunning)
    {
        int activeSockets = 0;
        int totalNewPacketsSent = 0;
        int totalRetransmissions = 0;

        // Process each transport Socket
        for (int SocketId = 0; SocketId < KTP_MAX_SOCKETS; SocketId++)
        {
            // Try to acquire exclusive access
            if (pthread_mutex_trylock(&ktpSockets[SocketId].socket_mutex) != 0)
                continue; // Skip if in use by another thread

            // Verify Socket state
            if (!ktpSockets[SocketId].is_allocated || !ktpSockets[SocketId].is_bound)
            {
                pthread_mutex_unlock(&ktpSockets[SocketId].socket_mutex);
                continue;
            }

            activeSockets++;

            // Get current timestamp for timeout checks
            struct timeval currentTimestamp;
            gettimeofday(&currentTimestamp, NULL);

            // RELIABILITY: Handle retransmissions for timed-out packets
            int retransmitted = handle_Socket_timeouts(SocketId, &currentTimestamp);
            totalRetransmissions += retransmitted;
            retransmissions[SocketId] += retransmitted;

            // Check if flow control is limiting transmission
            if (is_flow_controlled(SocketId))
            {
                flowControlHits[SocketId]++;

                if (flowControlHits[SocketId] % 10 == 0)
                {
                    fprintf(stdout, COLOR_BLUE "KTP: Socket %d: Window full (size=%d)\n" COLOR_RESET,
                            SocketId, ktpSockets[SocketId].swnd.size);
                }
            }

            // THROUGHPUT: Send new packets as window permits
            int sentPackets = transmit_new_packets(SocketId, txPackets);
            totalNewPacketsSent += sentPackets;

            // Release Socket
            pthread_mutex_unlock(&ktpSockets[SocketId].socket_mutex);
        }

        // Adapt sleep time based on activity
        if (activeSockets > 0)
        {
            //  activity summary if anything happened
            if (totalNewPacketsSent > 0 || totalRetransmissions > 0)
            {
                // Activity summary with performance metrics
                // float retransmissionRate = totalNewPacketsSent > 0 ?
                //     (100.0f * totalRetransmissions) / (totalNewPacketsSent + totalRetransmissions) : 0.0f;

                fprintf(stdout, COLOR_BLUE "KTP: Activity summary - "
                                           "sent: %d new, %d retx, %d active sockets\n" COLOR_RESET,
                        totalNewPacketsSent, totalRetransmissions, activeSockets);
            }
            // More frequent checks when active
            usleep(KTP_TIMEOUT_SEC * 300000); // 30% of timeout value
        }
        else
        {
            // Sleep longer when no active Sockets
            usleep(KTP_TIMEOUT_SEC * 800000); // 80% of timeout value
        }
    }

    // Generate final statistics report
    fprintf(stdout, COLOR_YELLOW "KTP: S_thread shutting down\n" COLOR_RESET);

    for (int SocketId = 0; SocketId < KTP_MAX_SOCKETS; SocketId++)
    {
        if (txPackets[SocketId] > 0)
        {
            float retransmissionRate = txPackets[SocketId] > 0 ? (100.0 * retransmissions[SocketId]) / txPackets[SocketId] : 0.0;

            fprintf(stdout, COLOR_YELLOW "KTP: Socket %d statistics - "
                                         "%u packets sent, %u retransmitted (%.1f%%), "
                                         "%u flow control pauses\n" COLOR_RESET,
                    SocketId,
                    txPackets[SocketId],
                    retransmissions[SocketId],
                    retransmissionRate,
                    flowControlHits[SocketId]);
        }
    }

    fprintf(stdout, COLOR_YELLOW "KTP: S_thread terminated\n" COLOR_RESET);
    return NULL;
}

/**
 * Verifies if process still exists
 *
 * @param processId Process ID to check
 * @return 1 if running, 0 if terminated
 */
static int is_process_running(pid_t processId)
{
    if (processId <= 0)
    {
        return 0; // Invalid PID
    }

    // Test if process exists by sending null signal
    return (kill(processId, 0) == 0 || errno != ESRCH);
}

/**
 * Purges network buffers for a specific Socket
 *
 * @param SocketIdx Socket index to reset
 */
static void purge_Socket_buffers(int SocketIdx)
{
    int i;

    // Reset transmission buffer data
    for (i = 0; i < KTP_SEND_BUFFER_SIZE; i++)
    {
        memset(ktpSockets[SocketIdx].send_buffer[i], 0, KTP_MSG_SIZE);
        ktpSockets[SocketIdx].send_buffer_occ[i] = 0;
    }

    // Reset reception buffer data
    for (i = 0; i < KTP_RECV_BUFFER_SIZE; i++)
    {
        memset(ktpSockets[SocketIdx].recv_buffer[i], 0, KTP_MSG_SIZE);
    }

    // Reset sequence tracking array
    memset(ktpSockets[SocketIdx].rwnd.received_msgs, 0,
           sizeof(ktpSockets[SocketIdx].rwnd.received_msgs));
}

/**
 * Resets protocol state of an Socket
 *
 * @param SocketIdx Socket index to reset
 */
static void reset_Socket_state(int SocketIdx)
{
    // Reset transmit window state
    ktpSockets[SocketIdx].swnd.base = 0;
    ktpSockets[SocketIdx].swnd.next_seq_num = 0;
    ktpSockets[SocketIdx].swnd.num_unacked = 0;

    // Reset receive window state
    ktpSockets[SocketIdx].rwnd.expected_seq_num = 0;
    ktpSockets[SocketIdx].rwnd.buffer_write_pos = 0;
    ktpSockets[SocketIdx].rwnd.buffer_read_pos = 0;
    ktpSockets[SocketIdx].rwnd.buffer_occupied = 0;
    ktpSockets[SocketIdx].rwnd.last_ack_sent = 255;
    ktpSockets[SocketIdx].rwnd.nospace_flag = 0;
}

/**
 * Reclaims a single abandoned Socket
 *
 * @param SocketIdx Socket index to reclaim
 * @return 1 if Socket was reclaimed, 0 otherwise
 */
static int reclaim_orphaned_Socket(int SocketIdx)
{
    // Skip unallocated sockets
    if (!ktpSockets[SocketIdx].is_allocated)
    {
        return 0;
    }

    pid_t owningProcess = ktpSockets[SocketIdx].pid;

    // Check if process still exists
    if (is_process_running(owningProcess))
    {
        return 0; // Process still active, nothing to do
    }

    // Log reclamation
    fprintf(stdout, BOLD_RED "G_thread: Reclaiming Socket %d from terminated process %d\n" COLOR_RESET, SocketIdx, owningProcess);

    // Reset socket allocation state
    ktpSockets[SocketIdx].is_allocated = 0;
    ktpSockets[SocketIdx].is_bound = 0;
    ktpSockets[SocketIdx].bind_requested = 0;
    ktpSockets[SocketIdx].pid = 0;

    // Clean up network buffers
    purge_Socket_buffers(SocketIdx);

    // Reset protocol state
    reset_Socket_state(SocketIdx);

    return 1; // Successfully reclaimed
}

/**
 * Resource monitoring thread - recovers abandoned network Sockets
 *
 * @param arg Thread parameter (unused)
 * @return Always NULL
 */
void *G_thread(void *arg)
{
    fprintf(stdout, COLOR_BLUE "G_thread: Garbage collector thread initialized\n" COLOR_RESET);

    // Scan configuration
    const int SCAN_INTERVAL_BASE = 8;   // Base interval between scans in seconds
    const int SCAN_INTERVAL_JITTER = 3; // Random jitter to add to scan interval
    const int MAX_BATCH_SIZE = 4;       // Maximum sockets to reclaim in one cycle

    // Runtime statistics
    unsigned int scanCount = 0;
    unsigned int totalReclaimed = 0;

    // Main monitoring loop
    while (isRunning)
    {
        scanCount++;
        int batchCounter = 0;
        int reclaimedInScan = 0;

        fprintf(stdout, COLOR_BLUE "G_thread: Beginning scan cycle #%u\n" COLOR_RESET,
                scanCount);

        // Start with reverse order to optimize common allocation patterns
        // (Higher indices are often allocated more recently)
        for (int SocketIdx = KTP_MAX_SOCKETS - 1;
             SocketIdx >= 0 && batchCounter < MAX_BATCH_SIZE;
             SocketIdx--)
        {
            // Try to acquire mutex without blocking
            if (pthread_mutex_trylock(&ktpSockets[SocketIdx].socket_mutex) != 0)
            {
                continue; // Skip if locked by another thread
            }

            // Process Socket and track results
            if (reclaim_orphaned_Socket(SocketIdx))
            {
                reclaimedInScan++;
                totalReclaimed++;
                batchCounter++;
            }

            // Release mutex
            pthread_mutex_unlock(&ktpSockets[SocketIdx].socket_mutex);
        }

        // Log results if Sockets were reclaimed
        if (reclaimedInScan > 0)
        {
            fprintf(stdout, COLOR_GREEN "G_thread: Reclaimed %d Sockets in scan cycle #%u\n" COLOR_RESET, reclaimedInScan, scanCount);
        }

        // Calculate next scan interval with jitter to avoid synchronization issues
        int sleepDuration = SCAN_INTERVAL_BASE + (rand() % SCAN_INTERVAL_JITTER);

        // Adapt scan frequency based on activity
        if (reclaimedInScan > 0)
        {
            // More frequent scans if we found orphaned resources
            sleepDuration = sleepDuration / 2;

            // Ensure minimum wait time
            if (sleepDuration < 2)
                sleepDuration = 2;
        }

        // Wait until next scan cycle
        sleep(sleepDuration);
    }

    // Final report
    fprintf(stdout, COLOR_BLUE "G_thread: Terminating after %u scans, reclaimed %u orphaned Sockets\n" COLOR_RESET, scanCount, totalReclaimed);

    return NULL;
}

/**
 * Protocol service entry point
 *
 * Initializes and manages the transport protocol service lifecycle
 */
int main(int argc, char **argv)
{
    int exitStatus = EXIT_SUCCESS;
    time_t startTime;
    char timeBuffer[64];
    pthread_t threadHandles[3] = {0};
    const char *threadNames[3] = {"Receiver", "Sender", "GarbageCollector"};
    void *(*threadFunctions[3])(void *) = {
        &R_thread,
        &S_thread,
        &G_thread};
    int activeThreadCount = 0;

    // Log startup information with timestamp
    time(&startTime);
    strftime(timeBuffer, sizeof(timeBuffer), "%Y-%m-%d %H:%M:%S", localtime(&startTime));
    printf(COLOR_GREEN "KTP Manager: Starting at %s\n" COLOR_RESET, timeBuffer);

    // Register termination handlers
    struct sigaction terminationHandler;
    memset(&terminationHandler, 0, sizeof(terminationHandler));
    terminationHandler.sa_handler = handle_signal;
    sigaction(SIGINT, &terminationHandler, NULL);
    sigaction(SIGTERM, &terminationHandler, NULL);
    sigaction(SIGHUP, &terminationHandler, NULL);

    // Initialize entropy source with multiple seeds
    unsigned int randomSeed = (unsigned int)time(NULL) ^ (getpid() << 16);
    srand(randomSeed);
    // printf(COLOR_BLUE "KTP Manager: Random generator initialized (seed=0x%08x)\n" COLOR_RESET, randomSeed);

    // Initialize communications infrastructure
    printf(COLOR_BLUE "KTP Manager: Initializing shmem resources...\n" COLOR_RESET);
    if (init_shared_memory() != 0)
    {
        fprintf(stderr, COLOR_RED "KTP Manager: Failed to initialize shmem resources\n" COLOR_RESET);
        return EXIT_FAILURE;
    }

    // Launch service threads with robust error handling
    printf(COLOR_BLUE "KTP Manager: Launching protocol threads...\n" COLOR_RESET);

    // Create all required threads
    for (int i = 0; i < 3; i++)
    {
        if (pthread_create(&threadHandles[i], NULL, threadFunctions[i], NULL) != 0)
        {
            fprintf(stderr, COLOR_RED "KTP Manager: Failed to launch %s thread: %s\n" COLOR_RESET,
                    threadNames[i], strerror(errno));

            // Signal running threads to terminate
            isRunning = 0;

            // Wait for previously launched threads
            for (int j = 0; j < i; j++)
            {
                printf(COLOR_YELLOW "KTP Manager: Waiting for %s thread to terminate...\n" COLOR_RESET, threadNames[j]);
                pthread_join(threadHandles[j], NULL);
            }

            // Clean up and exit
            cleanup();
            return EXIT_FAILURE;
        }

        activeThreadCount++;
        printf(COLOR_GREEN "KTP Manager: %s thread started (tid=%lu)\n" COLOR_RESET,
               threadNames[i], (unsigned long)threadHandles[i]);
    }

    // Service monitoring loop
    printf(COLOR_GREEN "KTP Manager: All subsystems operational\n" COLOR_RESET);

    // Periodic status reporting during operation
    int monitorCycle = 0;
    while (isRunning)
    {
        sleep(5);
        monitorCycle++;

        if (monitorCycle % 60 == 0)
        { // Report every 5 minutes
            time_t currentTime;
            time(&currentTime);
            double uptime = difftime(currentTime, startTime);

            // Format uptime as days:hours:minutes
            int days = (int)(uptime / 86400);
            int hours = (int)((uptime - days * 86400) / 3600);
            int minutes = (int)((uptime - days * 86400 - hours * 3600) / 60);

            printf(COLOR_BLUE "KTP Manager: Status - operational for %d days, %d hours, %d minutes\n" COLOR_RESET, days, hours, minutes);
        }
    }

    // Coordinated shutdown sequence
    printf(COLOR_YELLOW "KTP Manager: Initiating shutdown sequence\n" COLOR_RESET);

    // Join threads in reverse order (resource monitor first, packet delivery second, ingress last)
    for (int i = activeThreadCount - 1; i >= 0; i--)
    {
        printf(COLOR_YELLOW "KTP Manager: Waiting for %s thread to complete...\n" COLOR_RESET, threadNames[i]);

        // Set timeout for thread termination
        struct timespec timeout;
        clock_gettime(CLOCK_REALTIME, &timeout);
        timeout.tv_sec += 5; // 5-second timeout

        // Wait for thread with timeout
        int joinResult = pthread_join(threadHandles[i], NULL);
        if (joinResult != 0)
        {
            fprintf(stderr, COLOR_RED "KTP Manager: %s thread did not terminate gracefully: %s\n" COLOR_RESET, threadNames[i], strerror(joinResult));
            exitStatus = EXIT_FAILURE;
        }
        else
        {
            printf(COLOR_GREEN "KTP Manager: %s thread terminated successfully\n" COLOR_RESET, threadNames[i]);
        }
    }

    // Final resource cleanup
    cleanup();

    // Service termination
    time_t endTime;
    time(&endTime);
    strftime(timeBuffer, sizeof(timeBuffer), "%Y-%m-%d %H:%M:%S", localtime(&endTime));

    double runTime = difftime(endTime, startTime);
    printf(COLOR_GREEN "KTP Manager: Successfully terminated at %s (runtime: %.1f seconds)\n" COLOR_RESET, timeBuffer, runTime);

    return exitStatus;
}