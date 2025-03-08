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
#include "ksocket.h"

/* Terminal color codes for log output */
#define BOLD_CYAN    "\033[1;36m"
#define COLOR_BLUE    "\033[0;36m"
#define COLOR_RESET   "\033[0m"
#define COLOR_MAGENTA "\033[0;35m"  
#define BOLD_RED      "\033[1;31m" 
#define COLOR_RED      "\033[0;31m"  
#define COLOR_GREEN    "\033[0;32m" 
#define COLOR_YELLOW   "\033[0;33m"


/* Global state variables */
static int isRunning            = 1;  /* Flag controlling thread execution */
static int shmHandle            = -1; /* Shared memory ID */
static ktp_socket_t* ktpSockets = NULL; /* Socket array in shared memory */

/* Thread function prototypes */
void* receiver_thread(void* arg);
void* sender_thread(void* arg);
void* garbage_collector_thread(void* arg);

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
 * Initialize shared memory segment for KTP sockets
 * 
 * @return 0 on success, -1 on failure
 */
int init_shared_memory() 
{
    /* Generate key for shared memory segment */
    key_t shmKey = ftok("/tmp", 'K');
    if (shmKey == -1) 
    {
        perror(COLOR_MAGENTA "KTP Manager: Key generation failed");
        return -1;
    }
    
    /* Create shared memory segment */
    shmHandle = shmget(shmKey, sizeof(ktp_socket_t) * KTP_MAX_SOCKETS, IPC_CREAT | 0666);
    if (shmHandle == -1) 
    {
        perror(COLOR_MAGENTA "KTP Manager: Shared memory allocation failed");
        return -1;
    }
    
    /* Attach to the shared memory segment */
    ktpSockets = (ktp_socket_t*)shmat(shmHandle, NULL, 0);
    if (ktpSockets == (void*)-1) 
    {
        perror(COLOR_MAGENTA "KTP Manager: Memory attachment failed");
        return -1;
    }
    
    /* Initialize the shared memory */
    for (int i = 0; i < KTP_MAX_SOCKETS; i++) 
    {
        /* Zero out the socket structure */
        memset(&ktpSockets[i], 0, sizeof(ktp_socket_t));
        
        /* Create a UDP socket for this slot */
        int udpHandle = socket(AF_INET, SOCK_DGRAM, 0);
        if (udpHandle < 0) 
        {
            perror(COLOR_MAGENTA "KTP Manager: UDP socket creation failed");
            continue;  /* Skip this slot if socket creation fails */
        }
        
        /* Store socket descriptor and mark as available */
        ktpSockets[i].udp_sockfd = udpHandle;
        ktpSockets[i].is_allocated = 0;
        
        /* Initialize mutex with process-shared attribute */
        pthread_mutexattr_t mutexAttrs;
        pthread_mutexattr_init(&mutexAttrs);
        pthread_mutexattr_setpshared(&mutexAttrs, PTHREAD_PROCESS_SHARED);
        pthread_mutex_init(&ktpSockets[i].socket_mutex, &mutexAttrs);
        pthread_mutexattr_destroy(&mutexAttrs);
        
        printf(COLOR_MAGENTA "KTP Manager: Created UDP socket %d with descriptor %d\n", i, udpHandle);
    }
    
    printf(COLOR_MAGENTA "KTP Manager: Memory segment initialized for %d network sockets\n", KTP_MAX_SOCKETS);
    return 0;
}

/**
 * Release allocated resources
 */
void cleanup() 
{
    if (ktpSockets != NULL && ktpSockets != (void*)-1) 
    {
        /* Detach from shared memory */
        shmdt(ktpSockets);
    }
    
    if (shmHandle != -1) 
    {
        /* Remove shared memory segment */
        shmctl(shmHandle, IPC_RMID, NULL);
    }
    
    printf(COLOR_MAGENTA "KTP Manager: System resources released successfully\n");
}

/**
 * Main entry point for the KTP daemon
 */
int main() 
{
    /* Set up signal handlers for graceful termination */
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    
    /* Initialize random number generator for packet loss simulation */
    srand(time(NULL));
    
    /* Initialize shared memory */
    if (init_shared_memory() != 0) 
    {
        fprintf(stderr, COLOR_MAGENTA "KTP Manager: Memory initialization failed\n");
        return 1;
    }
    
    /* Thread handles */
    pthread_t rxThread, txThread, gcThread;
    
    /* Start the receiver thread (R) */
    if (pthread_create(&rxThread, NULL, receiver_thread, NULL) != 0) 
    {
        perror(COLOR_MAGENTA "KTP Manager: Receiver thread creation failed");
        cleanup();
        return 1;
    }
    
    /* Start the sender thread (S) */
    if (pthread_create(&txThread, NULL, sender_thread, NULL) != 0) 
    {
        perror(COLOR_MAGENTA "KTP Manager: Sender thread creation failed");
        isRunning = 0;  /* Signal other threads to terminate */
        pthread_join(rxThread, NULL);
        cleanup();
        return 1;
    }
    
    /* Start the garbage collector thread (G) */
    if (pthread_create(&gcThread, NULL, garbage_collector_thread, NULL) != 0) 
    {
        perror(COLOR_MAGENTA "KTP Manager: Garbage collector thread creation failed");
        isRunning = 0;  /* Signal other threads to terminate */
        pthread_join(rxThread, NULL);
        pthread_join(txThread, NULL);
        cleanup();
        return 1;
    }
    
    printf(COLOR_MAGENTA "KTP Manager: Protocol service initialized. All threads active.\n");
    
    /* Keep main thread running until signaled to stop */
    while (isRunning) 
    {
        sleep(1);
    }
    
    /* Wait for all threads to terminate */
    printf(COLOR_MAGENTA "KTP Manager: Waiting for thread termination...\n");
    pthread_join(rxThread, NULL);
    pthread_join(txThread, NULL);
    pthread_join(gcThread, NULL);
    
    /* Perform final cleanup */
    cleanup();
    
    printf(COLOR_MAGENTA "KTP Manager: Service terminated successfully\n");
    return 0;
}

/**
 * Receiver thread (R) - Processes incoming packets and sends acknowledgments
 * 
 * @param arg Thread argument (unused)
 * @return Always NULL
 */
void* receiver_thread(void* arg) 
{
    printf(COLOR_RESET "KTP Receiver thread started\n");

    int packetCount = 0;
    int droppedCount = 0;
    
    fd_set readFds;
    struct timeval timeVal;
    
    /* Track buffer-free notifications needed per socket */
    int bufferFreeAcksNeeded[KTP_MAX_SOCKETS];
    for (int i = 0; i < KTP_MAX_SOCKETS; i++) 
    {
        bufferFreeAcksNeeded[i] = 0;
    }

    /* Main thread loop */
    while (isRunning) 
    {
        /* Process binding requests from client applications */
        for (int i = 0; i < KTP_MAX_SOCKETS; i++) 
        {
            if (pthread_mutex_trylock(&ktpSockets[i].socket_mutex) == 0) 
            {
                const int isBindPending = 
                    ktpSockets[i].is_allocated && 
                    ktpSockets[i].bind_requested && 
                    !ktpSockets[i].is_bound;
                    
                if (isBindPending) 
                {
                    printf(COLOR_GREEN "KTP: Processing binding request for socket %d\n", i);
                    
                    /* Close and recreate UDP socket to ensure clean state */
                    close(ktpSockets[i].udp_sockfd);
                    ktpSockets[i].udp_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
                    
                    /* Bind the socket to the requested address */
                    if (bind(ktpSockets[i].udp_sockfd, 
                            (struct sockaddr*)&ktpSockets[i].src_addr, 
                            sizeof(struct sockaddr_in)) < 0) 
                    {
                        perror("KTP: Socket binding operation failed");
                        /* Don't set is_bound - client will time out */
                    } 
                    else 
                    {
                        /* Binding successful */
                        ktpSockets[i].is_bound = 1;
                        ktpSockets[i].bind_requested = 0;
                        printf(COLOR_GREEN "KTP: Socket %d bound successfully to network endpoint\n", i);
                    }
                }
                pthread_mutex_unlock(&ktpSockets[i].socket_mutex);
            }
        }
        
        /* Set up file descriptor set for select() */
        FD_ZERO(&readFds);
        int maxFd = -1;
        
        /* Add all active UDP sockets to the set */
        for (int i = 0; i < KTP_MAX_SOCKETS; i++) 
        {
            if (pthread_mutex_trylock(&ktpSockets[i].socket_mutex) == 0) 
            {
                const int isSocketActive = 
                    ktpSockets[i].is_allocated && 
                    ktpSockets[i].is_bound && 
                    ktpSockets[i].udp_sockfd >= 0;
                    
                if (isSocketActive) 
                {
                    int fd = ktpSockets[i].udp_sockfd;
                    
                    /* Validate socket descriptor */
                    int sockError = 0;
                    socklen_t errLen = sizeof(sockError);
                    int checkResult = getsockopt(fd, SOL_SOCKET, SO_ERROR, &sockError, &errLen);
                    
                    if (checkResult == 0 && sockError == 0) 
                    {
                        /* Socket is valid, add to select set */
                        FD_SET(fd, &readFds);
                        if (fd > maxFd) 
                        {
                            maxFd = fd;
                        }
                    } 
                    else 
                    {
                        printf(COLOR_GREEN "KTP: Socket %d: Invalid descriptor %d (result=%d, error=%d)\n", 
                            i, fd, checkResult, sockError);
                        /* Socket appears invalid but marked as allocated - fix this */
                        ktpSockets[i].is_allocated = 0;
                        ktpSockets[i].udp_sockfd = -1;
                    }
                }
                pthread_mutex_unlock(&ktpSockets[i].socket_mutex);
            }
        }
        
        /* If no active sockets, just wait a bit and try again */
        if (maxFd < 0) 
        {
            usleep(100000); /* 100ms */
            continue;
        }
        
        /* Set timeout for select */
        timeVal.tv_sec = 1;  /* 1 second */
        timeVal.tv_usec = 0;
        
        /* Wait for incoming data on any socket */
        int selectResult = select(maxFd + 1, &readFds, NULL, NULL, &timeVal);
        
        if (selectResult < 0) 
        {
            /* Handle select error */
            if (isRunning) { /* Only log if we're not shutting down */
                perror("KTP: Network polling error");
            }
            continue;
        }
        
        /* Process each socket that has data available */
        for (int i = 0; i < KTP_MAX_SOCKETS; i++) 
        {
            if (pthread_mutex_trylock(&ktpSockets[i].socket_mutex) == 0) 
            {
                if (ktpSockets[i].is_allocated && ktpSockets[i].is_bound) 
                {
                    int fd = ktpSockets[i].udp_sockfd;
                    
                    if (FD_ISSET(fd, &readFds)) 
                    {
                        /* Receive incoming message */
                        ktp_message_t message;
                        struct sockaddr_in srcAddr;
                        socklen_t addrLen = sizeof(srcAddr);
                        
                        ssize_t bytesReceived = recvfrom(fd, &message, sizeof(message), 0,
                                                        (struct sockaddr *)&srcAddr, &addrLen);

                        packetCount++;
                        
                        /* Check for simulated packet loss */
                        if (dropMessage(KTP_PACKET_LOSS_PROB)) 
                        {
                            printf(COLOR_RED "KTP: Socket %d: Incoming packet deliberately dropped (simulated loss)\n", i);
                            droppedCount++;
                            pthread_mutex_unlock(&ktpSockets[i].socket_mutex);
                            continue;
                        }
                        
                        /* Handle receive errors */
                        if (bytesReceived <= 0) 
                        {
                            pthread_mutex_unlock(&ktpSockets[i].socket_mutex);
                            continue;
                        }
                        
                        /* Process message based on type */
                        if (message.header.type == KTP_TYPE_DATA) 
                        {
                            /* Reset buffer free notification counter */
                            bufferFreeAcksNeeded[i] = 0;
                            
                            /* Log received data message */
                            printf(COLOR_GREEN "KTP: Socket %d: Data packet received with seq=%d\n", 
                                i, message.header.seq_num);
                            
                            const uint8_t seqNum = message.header.seq_num;
                            const uint8_t expectedSeqNum = ktpSockets[i].rwnd.expected_seq_num;
                            
                            /* Check for duplicate message */
                            int isDuplicate = 0;
                            for (int j = 0; j < KTP_RECV_BUFFER_SIZE; j++) 
                            {
                                if (ktpSockets[i].rwnd.received_msgs[j] == seqNum) 
                                {
                                    isDuplicate = 1;
                                    break;
                                }
                            }
                            
                            /* Calculate acceptable sequence number range (window) */
                            int inWindow = 0;
                            const int windowEnd = (expectedSeqNum + ktpSockets[i].rwnd.size - 1) % 256;
                            
                            /* Check if sequence number is within window */
                            if (expectedSeqNum <= windowEnd) 
                            {
                                /* Normal case (window doesn't wrap) */
                                inWindow = (seqNum >= expectedSeqNum && seqNum <= windowEnd);
                            } 
                            else 
                            {
                                /* Window wraps around (crosses 255->0) */
                                inWindow = (seqNum >= expectedSeqNum || seqNum <= windowEnd);
                            }
                            
                            if (isDuplicate) 
                            {
                                /* For duplicate packets, just send ACK with current state */
                                ktp_message_t ackMsg;
                                memset(&ackMsg, 0, sizeof(ackMsg));
                                ackMsg.header.type = KTP_TYPE_ACK;
                                ackMsg.header.last_ack = ktpSockets[i].rwnd.last_ack_sent;
                                ackMsg.header.rwnd = ktpSockets[i].rwnd.size;
                                
                                printf(COLOR_GREEN "KTP: Socket %d: Sending ACK for duplicate packet, last_ack=%d\n", 
                                    i, ackMsg.header.last_ack);
                                
                                sendto(ktpSockets[i].udp_sockfd, &ackMsg, sizeof(ackMsg.header), 0,
                                        (struct sockaddr *)&ktpSockets[i].dst_addr, 
                                        sizeof(struct sockaddr_in));
                            }
                            else if (inWindow) 
                            {
                                /* Packet is within receive window - process it */
                                
                                /* Check if buffer has space */
                                if (ktpSockets[i].rwnd.buffer_occupied >= KTP_RECV_BUFFER_SIZE) 
                                {
                                    /* Buffer full - set flag and drop packet */
                                    ktpSockets[i].rwnd.nospace_flag = 1;
                                    ktpSockets[i].rwnd.size = 0;
                                    
                                    printf(COLOR_YELLOW "KTP: Socket %d: Receive buffer full, packet %d discarded\n", 
                                        i, seqNum);
                                    pthread_mutex_unlock(&ktpSockets[i].socket_mutex);
                                    continue;
                                }
                                
                                /* Store packet in receive buffer at calculated position */
                                const int writePos = ktpSockets[i].rwnd.buffer_write_pos;
                                const int offset = ((seqNum - expectedSeqNum + 256) % 256) % KTP_RECV_BUFFER_SIZE;
                                const int targetPos = (writePos + offset) % KTP_RECV_BUFFER_SIZE;

                                /* Copy message data to buffer */
                                memcpy(ktpSockets[i].recv_buffer[targetPos], message.data, KTP_MSG_SIZE);
                                
                                /* Mark sequence number as received */
                                ktpSockets[i].rwnd.received_msgs[targetPos] = seqNum;
                                
                                /* Advance expected sequence number for in-order packets */
                                while (ktpSockets[i].rwnd.received_msgs[ktpSockets[i].rwnd.buffer_write_pos] == 
                                    ktpSockets[i].rwnd.expected_seq_num) 
                                {
                                    /* Update state for each in-order packet */
                                    ktpSockets[i].rwnd.expected_seq_num = 
                                        (ktpSockets[i].rwnd.expected_seq_num + 1) % 256;
                                    ktpSockets[i].rwnd.buffer_write_pos = 
                                        (ktpSockets[i].rwnd.buffer_write_pos + 1) % KTP_RECV_BUFFER_SIZE;
                                    ktpSockets[i].rwnd.buffer_occupied++;
                                    ktpSockets[i].rwnd.size--;
                                }
                                
                                /* Update last_ack_sent */
                                ktpSockets[i].rwnd.last_ack_sent = (ktpSockets[i].rwnd.expected_seq_num - 1 + 256) % 256;
                                
                                /* Send ACK with updated state */
                                ktp_message_t ackMsg;
                                memset(&ackMsg, 0, sizeof(ackMsg));
                                ackMsg.header.type = KTP_TYPE_ACK;
                                ackMsg.header.last_ack = ktpSockets[i].rwnd.last_ack_sent;
                                ackMsg.header.rwnd = ktpSockets[i].rwnd.size;
                                
                                printf(COLOR_GREEN "KTP: Socket %d: Sending ACK, last_ack=%d, window=%d\n", 
                                    i, ackMsg.header.last_ack, ackMsg.header.rwnd);
                                
                                sendto(ktpSockets[i].udp_sockfd, &ackMsg, sizeof(ackMsg.header), 0,
                                    (struct sockaddr *)&ktpSockets[i].dst_addr, 
                                    sizeof(struct sockaddr_in));

                                /* Check if buffer is now full */
                                if (ktpSockets[i].rwnd.buffer_occupied >= KTP_RECV_BUFFER_SIZE) 
                                {
                                    ktpSockets[i].rwnd.nospace_flag = 1;
                                    ktpSockets[i].rwnd.size = 0;
                                    
                                    printf(COLOR_GREEN "KTP: Socket %d: Buffer now full after processing packet %d\n", 
                                        i, seqNum);
                                }
                            } 
                            else 
                            {
                                /* Sequence number outside window - discard */
                                printf(COLOR_RED "KTP: Socket %d: Packet outside window, seq=%d discarded\n", 
                                    i, seqNum);
                            }
                        }
                        else if (message.header.type == KTP_TYPE_ACK) 
                        {
                            /* Handle ACK message */
                            printf(COLOR_GREEN "KTP: Socket %d: ACK received, last_ack=%d, window=%d\n", 
                                i, message.header.last_ack, message.header.rwnd);
                            
                            const uint8_t lastAck = message.header.last_ack;
                            
                            /* Update send window size based on advertised receive window */
                            ktpSockets[i].swnd.size = message.header.rwnd;
                            
                            /* Process acknowledged packets */
                            int ackedCount = 0;
                            int foundAck = 0;
                            
                            /* Count acknowledged packets up to last_ack */
                            for (int j = 0; j < ktpSockets[i].swnd.num_unacked; j++) 
                            {
                                int windowIdx = (ktpSockets[i].swnd.base + j) % KTP_MAX_WINDOW_SIZE;
                                uint8_t seqNum = ktpSockets[i].swnd.seq_nums[windowIdx];
                                
                                ackedCount++;
                                
                                /* Check if we found the ack boundary */
                                if (seqNum == lastAck) 
                                {
                                    foundAck = 1;
                                    break;
                                }
                            }
                            
                            /* If we didn't find the ack in our window, it's a duplicate */
                            if (!foundAck) 
                            {
                                printf(COLOR_GREEN "KTP: Socket %d: Duplicate ACK %d, updating window only\n", 
                                    i, lastAck);
                                pthread_mutex_unlock(&ktpSockets[i].socket_mutex);
                                continue;
                            }
                            
                            /* Found valid ACK, process acknowledged packets */
                            printf(COLOR_GREEN "KTP: Socket %d: Processing ACK for %d packets up to seq %d\n", 
                                i, ackedCount, lastAck);
                            
                            /* Clear the acknowledged messages from buffer */
                            for (int j = 0; j < ackedCount; j++) 
                            {
                                int seqIdx = (ktpSockets[i].swnd.base + j) % KTP_SEND_BUFFER_SIZE;
                                
                                /* Clear buffer and mark as unoccupied */
                                memset(ktpSockets[i].send_buffer[seqIdx], 0, KTP_MSG_SIZE);
                                ktpSockets[i].send_buffer_occ[seqIdx] = 0;
                            }
                            
                            /* Slide window forward */
                            ktpSockets[i].swnd.base = (ktpSockets[i].swnd.base + ackedCount) % KTP_MAX_WINDOW_SIZE;
                            ktpSockets[i].swnd.num_unacked -= ackedCount;
                            
                            printf(COLOR_GREEN "KTP: Socket %d: Window advanced, base=%d, unacked=%d\n", 
                                i, ktpSockets[i].swnd.base, ktpSockets[i].swnd.num_unacked);
                        }
                    }
                }
                pthread_mutex_unlock(&ktpSockets[i].socket_mutex);
            }
        }
        
        /* Handle buffer space availability notifications */
        for (int i = 0; i < KTP_MAX_SOCKETS; i++) 
        {
            if (pthread_mutex_trylock(&ktpSockets[i].socket_mutex) == 0) 
            {
                if (ktpSockets[i].is_allocated && ktpSockets[i].is_bound) 
                {
                    /* Check if buffer was previously full but now has space */
                    const int bufferFreed = 
                        ktpSockets[i].rwnd.nospace_flag && 
                        ktpSockets[i].rwnd.buffer_occupied < KTP_RECV_BUFFER_SIZE;
                        
                    if (bufferFreed) 
                    {
                        /* Buffer has transitioned from full to having space */
                        ktpSockets[i].rwnd.nospace_flag = 0;
                        
                        /* Schedule multiple window update ACKs to ensure delivery */
                        bufferFreeAcksNeeded[i] = 10;
                        
                        printf(COLOR_GREEN "KTP: Socket %d: Buffer space available, scheduling update ACKs\n", i);
                    }
                    
                    /* Send any scheduled buffer-free notification ACKs */
                    if (bufferFreeAcksNeeded[i] > 0) 
                    {
                        ktp_message_t ackMsg;
                        memset(&ackMsg, 0, sizeof(ackMsg));
                        ackMsg.header.type = KTP_TYPE_ACK;
                        ackMsg.header.last_ack = ktpSockets[i].rwnd.last_ack_sent;
                        ackMsg.header.rwnd = ktpSockets[i].rwnd.size;
                        
                        printf(COLOR_GREEN "KTP: Socket %d: Sending capacity notification %d/10: ack=%d, window=%d\n", 
                            i, 11 - bufferFreeAcksNeeded[i], 
                            ackMsg.header.last_ack, ackMsg.header.rwnd);
                        
                        sendto(ktpSockets[i].udp_sockfd, &ackMsg, sizeof(ackMsg.header), 0,
                            (struct sockaddr *)&ktpSockets[i].dst_addr, 
                            sizeof(struct sockaddr_in));
                        
                        bufferFreeAcksNeeded[i]--;
                    }
                }
                pthread_mutex_unlock(&ktpSockets[i].socket_mutex);
            }
        }
    }
    
    /* Print packet loss statistics before exiting */
    if (packetCount > 0) 
    {
        printf(COLOR_YELLOW "KTP: Network statistics: %d total packets, %d dropped (%.2f%%)\n", 
            packetCount, droppedCount, (droppedCount * 100.0) / packetCount);
    }
    printf(COLOR_RESET "KTP Receiver thread terminated\n");
    return NULL;
}

/**
 * Sender thread (S) - Transmits new packets and handles retransmissions
 * 
 * @param arg Thread argument (unused)
 * @return Always NULL
 */
void* sender_thread(void* arg) 
{
    printf(COLOR_RESET "KTP Sender thread started\n");
    struct timeval currentTime;

    /* Track transmission statistics per socket */
    int txPacketsPerSocket[KTP_MAX_SOCKETS];
    for (int i = 0; i < KTP_MAX_SOCKETS; i++) 
    {
        txPacketsPerSocket[i] = 0;
    }
    
    /* Main thread loop */
    while (isRunning) 
    {
        /* Process each socket */
        for (int i = 0; i < KTP_MAX_SOCKETS; i++) 
        {
            /* Skip if we can't lock the mutex (socket in use by another thread) */
            if (pthread_mutex_trylock(&ktpSockets[i].socket_mutex) != 0) 
            {
                continue;
            }
            
            /* Process only allocated and bound sockets */
            const int isActive = ktpSockets[i].is_allocated && ktpSockets[i].is_bound;
            if (!isActive) 
            {
                pthread_mutex_unlock(&ktpSockets[i].socket_mutex);
                continue;
            }
            
            /* Get current time for timeout calculations */
            gettimeofday(&currentTime, NULL);
            
            /* Check for timeouts and retransmit if needed */
            int windowTimeout = 0;

            /* First pass: check if any message has timed out */
            for (int j = 0; j < ktpSockets[i].swnd.num_unacked; j++) 
            {
                /* Calculate index in circular buffer */
                int windowIdx = (ktpSockets[i].swnd.base + j) % KTP_MAX_WINDOW_SIZE;
                
                /* Calculate elapsed time since last transmission */
                long timeDiffSec = currentTime.tv_sec - ktpSockets[i].swnd.send_times[windowIdx].tv_sec;
                long timeDiffUsec = currentTime.tv_usec - ktpSockets[i].swnd.send_times[windowIdx].tv_usec;
                double timeDiff = timeDiffSec + (timeDiffUsec / 1000000.0);
                
                /* Check against timeout threshold */
                if (timeDiff >= KTP_TIMEOUT_SEC) 
                {
                    windowTimeout = 1;
                    break;  /* One timeout is enough to trigger retransmission */
                }
            }

            /* If any message timed out, retransmit the entire window */
            if (windowTimeout) 
            {
                printf(COLOR_BLUE "KTP: Socket %d: Timeout detected, retransmitting %d pending packets\n", 
                    i, ktpSockets[i].swnd.num_unacked);
                
                /* Retransmit all messages in the current window */
                for (int j = 0; j < ktpSockets[i].swnd.num_unacked; j++) 
                {
                /* Calculate index in circular buffer */
                int windowIdx = (ktpSockets[i].swnd.base + j) % KTP_MAX_WINDOW_SIZE;
                /* Get sequence number for this packet */
                uint8_t seqNum = ktpSockets[i].swnd.seq_nums[windowIdx];
                /* Calculate buffer index */
                int seqIdx = (ktpSockets[i].swnd.base + j) % KTP_SEND_BUFFER_SIZE;
                
                /* Create KTP message for retransmission */
                ktp_message_t message;
                message.header.type = KTP_TYPE_DATA;
                message.header.seq_num = seqNum;
                message.header.rwnd = ktpSockets[i].rwnd.size;
                message.header.last_ack = ktpSockets[i].rwnd.expected_seq_num - 1;
                
                /* Copy data from send buffer */
                memcpy(message.data, ktpSockets[i].send_buffer[seqIdx], 
                        KTP_MSG_SIZE);
                
                /* Send the message */
                sendto(ktpSockets[i].udp_sockfd, &message, sizeof(message), 0,
                        (struct sockaddr *)&ktpSockets[i].dst_addr, 
                        sizeof(struct sockaddr_in));
                    
                /* Update statistics */
                txPacketsPerSocket[i]++;
                
                /* Update send timestamp for timeout calculation */
                gettimeofday(&ktpSockets[i].swnd.send_times[windowIdx], NULL);
            }
        }
        
        /* Process new messages to send if window not full */
        while (ktpSockets[i].swnd.num_unacked < ktpSockets[i].swnd.size) 
        {
            /* Calculate next sequence index in buffer */
            int nextSeqIdx = (ktpSockets[i].swnd.base + ktpSockets[i].swnd.num_unacked) % KTP_SEND_BUFFER_SIZE;
            
            /* Check if there's a message ready to send */
            if (ktpSockets[i].send_buffer_occ[nextSeqIdx] == 0) 
            {
                /* No more messages queued for sending */
                break;
            }
            
            /* Create KTP message */
            ktp_message_t message;
            message.header.type = KTP_TYPE_DATA;
            message.header.seq_num = ktpSockets[i].swnd.next_seq_num;
            message.header.rwnd = ktpSockets[i].rwnd.size;
            message.header.last_ack = ktpSockets[i].rwnd.expected_seq_num - 1;
            
            /* Copy data from send buffer */
            memcpy(message.data, ktpSockets[i].send_buffer[nextSeqIdx], 
                    KTP_MSG_SIZE);
            
            /* Store sequence number in window tracking */
            int windowIdx = (ktpSockets[i].swnd.base + ktpSockets[i].swnd.num_unacked) % KTP_MAX_WINDOW_SIZE;
            ktpSockets[i].swnd.seq_nums[windowIdx] = message.header.seq_num;
            
            /* Record send time for timeout calculation */
            gettimeofday(&ktpSockets[i].swnd.send_times[windowIdx], NULL);
            
            /* Send the message */
            sendto(ktpSockets[i].udp_sockfd, &message, sizeof(message), 0,
                    (struct sockaddr *)&ktpSockets[i].dst_addr, 
                    sizeof(struct sockaddr_in));
            
            /* Update statistics */
            txPacketsPerSocket[i]++;
            
            printf(COLOR_BLUE "KTP: Socket %d: New packet sent with sequence %d\n", 
                    i, message.header.seq_num);
            
            /* Update window state */
            ktpSockets[i].swnd.next_seq_num = (ktpSockets[i].swnd.next_seq_num + 1) % 256;
            ktpSockets[i].swnd.num_unacked++;
        }
        
        pthread_mutex_unlock(&ktpSockets[i].socket_mutex);
    }
    
    /* Sleep for half the timeout period before next iteration */
    usleep(KTP_TIMEOUT_SEC * 1000000 / 2);
}

/* Print transmission statistics before exiting */
for (int i = 0; i < KTP_MAX_SOCKETS; i++) 
{
    if (txPacketsPerSocket[i] > 0) 
    {
        printf(COLOR_RESET "KTP: Socket %d: Total %d packets transmitted\n", 
                i, txPacketsPerSocket[i]);
    }
}

printf(COLOR_RESET "KTP Sender thread terminated\n");
return NULL;
}

/**
 * Garbage collector thread (G) - Cleans up resources for terminated processes
 * 
 * @param arg Thread argument (unused)
 * @return Always NULL
 */
void* garbage_collector_thread(void* arg) 
{
    printf(COLOR_RESET "KTP Garbage collector thread started\n");
    
    /* Constants */
    const int CLEANUP_INTERVAL = 5; /* Seconds between cleanup cycles */
    
    /* Main thread loop */
    while (isRunning) 
    {
        /* Check each socket */
        for (int i = 0; i < KTP_MAX_SOCKETS; i++) 
        {
            /* Try to lock the socket mutex */
            if (pthread_mutex_trylock(&ktpSockets[i].socket_mutex) == 0) 
            {
                /* Check only allocated sockets */
                if (ktpSockets[i].is_allocated) 
                {
                    pid_t procId = ktpSockets[i].pid;
                    
                    /* Check if the process is still running */
                    if (kill(procId, 0) == -1) 
                    {
                        /* Process is no longer running - clean up the socket */
                        printf(BOLD_RED "KTP: Cleanup: Process %d terminated, recovering socket %d\n", 
                               procId, i);
                        
                        /* Release the socket */
                        ktpSockets[i].is_allocated = 0;
                        ktpSockets[i].pid = 0;
                        ktpSockets[i].is_bound = 0;
                        
                        /* Clear send buffer */
                        for (int j = 0; j < KTP_SEND_BUFFER_SIZE; j++) 
                        {
                            memset(ktpSockets[i].send_buffer[j], 0, KTP_MSG_SIZE);
                            ktpSockets[i].send_buffer_occ[j] = 0;
                        }
                        
                        /* Clear receive buffer */
                        for (int j = 0; j < KTP_RECV_BUFFER_SIZE; j++) 
                        {
                            memset(ktpSockets[i].recv_buffer[j], 0, KTP_MSG_SIZE);
                        }
                        
                        /* Reset tracking arrays */
                        memset(ktpSockets[i].rwnd.received_msgs, 0, 
                              sizeof(ktpSockets[i].rwnd.received_msgs));
                        
                        /* Clear window structures */
                        memset(&ktpSockets[i].swnd, 0, sizeof(ktpSockets[i].swnd));
                        memset(&ktpSockets[i].rwnd, 0, sizeof(ktpSockets[i].rwnd));
                    }
                }
                /* Unlock the mutex */
                pthread_mutex_unlock(&ktpSockets[i].socket_mutex);
            }
            /* If mutex is locked, skip this socket for now */
        }
        
        /* Sleep before next cleanup cycle */
        sleep(CLEANUP_INTERVAL);
    }
    
    printf(COLOR_RESET "KTP Garbage collector thread terminated\n");
    return NULL;
}