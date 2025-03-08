#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/time.h>
#include <stdint.h>
#include "ksocket.h"

static int running = 1;
static int shmid = -1;
static ktp_socket_t* ktp_sockets = NULL;
void handle_sig(int sig){
    printf("Received signal %d\n, exiting. \n", sig);
    running = 0;
}
int init_shared_memory() {
    // Generate key for shared memory
    key_t key = ftok("/", 'A');
    if (key == -1) {
        perror("ftok failed");
        return -1;
    }
    
    // Create shared memory segment
    shmid = shmget(key, sizeof(ktp_socket_t) * MAX_KTP_SOCK, IPC_CREAT | 0666);
    if (shmid == -1) {
        perror("shmget failed");
        return -1;
    }
    
    // Attach to the shared memory segment
    ktp_sockets = (ktp_socket_t*)shmat(shmid, NULL, 0);
    if (ktp_sockets == (void*)-1) {
        perror("shmat failed");
        return -1;
    }
    
    // Initialize the shared memory
    for (int i = 0; i < MAX_KTP_SOCK; i++) {
        memset(&ktp_sockets[i], 0, sizeof(ktp_socket_t));
        
        // Pre-create the UDP socket for this slot
        int udp_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (udp_sockfd < 0) {
            perror("Failed to create UDP socket");
            continue;  // Skip this slot if socket creation fails
        }
        
        // Store the socket descriptor in shared memory
        ktp_sockets[i].udp_sockfd = udp_sockfd;
        ktp_sockets[i].is_alloc = 0;  // Mark as available
        
        // Initialize mutex for each socket with process-shared attribute
        pthread_mutexattr_t attr;
        pthread_mutexattr_init(&attr);
        pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
        pthread_mutex_init(&ktp_sockets[i].mutex, &attr);
        pthread_mutexattr_destroy(&attr);
        
        printf("Pre-created UDP socket %d with fd %d\n", i, udp_sockfd);
    }
    
    printf("Shared memory initialized for KTP sockets\n");
    return 0;
}


void cleanup() {
    if (shmid != -1) {
        // Detach from shared memory
        if (ktp_sockets != NULL && shmdt(ktp_sockets) != -1) {
            shmdt(ktp_sockets);
        }
        
        if(shmid == -1) {
            perror("shmdt failed");
            exit(1);
        }
        // Remove shared memory segment
        shmctl(shmid, IPC_RMID, NULL);
    }
}

void* receiver_thread(void* arg) {
    printf("Receiver thread started\n");

    int total_received = 0, dropped = 0;
    
    fd_set read_fds;
    struct timeval tv;
    
    // Track how many buffer-free ACKs to send for each socket
    int buffer_free_acks_needed[MAX_KTP_SOCK];
    for (int i = 0; i < MAX_KTP_SOCK; i++) {
        buffer_free_acks_needed[i] = 0;
    }

    while (running) {
        // Process binding requests
        for (int i = 0; i < MAX_KTP_SOCK; i++) {
            if (ktp_sockets[i].bind_req && !ktp_sockets[i].is_bound) {
                pthread_mutex_lock(&ktp_sockets[i].mutex);
                
                if (bind(ktp_sockets[i].udp_sockfd, 
                         (struct sockaddr*)&ktp_sockets[i].src_addr, 
                         sizeof(struct sockaddr_in)) == 0) {
                    ktp_sockets[i].is_bound = 1;
                    printf("Socket %d bound successfully\n", i);
                } else {
                    perror("Failed to bind socket");
                }
                ktp_sockets[i].bind_req = 0;
                
                pthread_mutex_unlock(&ktp_sockets[i].mutex);
            }
        }
        
        // Set up select for UDP sockets
        FD_ZERO(&read_fds);
        int max_fd = -1;
        
        // Add all active UDP sockets to the set
        for (int i = 0; i < MAX_KTP_SOCK; i++) {
            if (pthread_mutex_trylock(&ktp_sockets[i].mutex) == 0) {
            // Only add valid sockets with valid file descriptors
            if (ktp_sockets[i].is_alloc && 
                ktp_sockets[i].is_bound && 
                ktp_sockets[i].udp_sockfd >= 0) {
                
                int fd = ktp_sockets[i].udp_sockfd;
                
                // Extra validation - check if socket is really valid
                int error = 0;
                socklen_t len = sizeof(error);
                int retval = getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len);
                
                if (retval == 0 && error == 0) {
                // Socket appears valid, add to set
                FD_SET(fd, &read_fds);
                if (fd > max_fd) {
                    max_fd = fd;
                }
                } else {
                printf("Socket %d: Invalid fd %d (retval=%d, error=%d)\n", i, fd, retval, error);
                // Socket is invalid but marked as allocated - fix this
                ktp_sockets[i].is_alloc = 0;
                ktp_sockets[i].udp_sockfd = -1;
                }
            }
            pthread_mutex_unlock(&ktp_sockets[i].mutex);
            }
        }
        // If no active sockets, just wait a bit
        if (max_fd < 0) {
            usleep(100000); // 100ms
            continue;
        }
        
        // Set timeout for select
        tv.tv_sec = 0;
        tv.tv_usec = 500000; // 500ms
        
        // Wait for incoming data
        int select_result = select(max_fd + 1, &read_fds, NULL, NULL, &tv);
        
        if (select_result < 0) {
            // Error in select
            if (running) { 
                perror("select error");
            }
            continue;
        } else if (select_result == 0) {
            // Timeout, continue to next iteration
            continue;
        }
        
        // Process sockets with data
        for (int i = 0; i < MAX_KTP_SOCK; i++) {
            if (ktp_sockets[i].is_alloc && ktp_sockets[i].is_bound) {
                int fd = ktp_sockets[i].udp_sockfd;
                
                if (fd >= 0 && FD_ISSET(fd, &read_fds)) {
                    // Lock the socket mutex for this operation
                    pthread_mutex_lock(&ktp_sockets[i].mutex);
                    
                    // Receive message
                    ktp_message_t message;
                    struct sockaddr_in src_addr;
                    socklen_t src_addr_len = sizeof(src_addr);
                    
                    ssize_t bytes_received = recvfrom(fd, &message, sizeof(message), 0,
                                                      (struct sockaddr*)&src_addr, &src_addr_len);
                    
                    total_received++;
                    
                    // Check for simulated packet loss
                    if (dropMessage(P)) {
                        printf("Socket %d: Dropped received message (simulated loss)\n", i);
                        dropped++;
                        pthread_mutex_unlock(&ktp_sockets[i].mutex);
                        continue;
                    }
                    
                    if (bytes_received <= 0) {
                        // Error or connection closed
                        pthread_mutex_unlock(&ktp_sockets[i].mutex);
                        continue;
                    }
                    
                    // Process based on message type
                    if (message.header.type == MSG_DATA) {
                        buffer_free_acks_needed[i] = 0; // Reset buffer_free_acks_needed
                        
                        printf("Socket %d: Received DATA message seq=%d\n", 
                               i, message.header.seq_num);
                        
                        uint8_t seq_num = message.header.seq_num;
                        uint8_t expected_seq_num = ktp_sockets[i].rwnd.expected_seq_num;
                        
                        // Check if this is a duplicate message
                        int is_duplicate = 0;
                        for (int j = 0; j < RECV_BUFSIZE; j++) {
                            if (ktp_sockets[i].rwnd.received_msgs[j] == seq_num) {
                                is_duplicate = 1;
                                break;
                            }
                        }
                        
                        // Check if sequence number is within window
                        int window_end = (expected_seq_num + ktp_sockets[i].rwnd.size - 1) % 256;
                        int in_window = 0;
                        
                        if (expected_seq_num <= window_end) {
                            // Window doesn't wrap around
                            in_window = (seq_num >= expected_seq_num && seq_num <= window_end);
                        } else {
                            // Window wraps around
                            in_window = (seq_num >= expected_seq_num || seq_num <= window_end);
                        }
                        
                        if (is_duplicate) {
                            // For duplicate packet, just send ACK
                            ktp_message_t ack_msg;
                            memset(&ack_msg, 0, sizeof(ack_msg));
                            ack_msg.header.type = MSG_ACK;
                            ack_msg.header.last_ack = ktp_sockets[i].rwnd.last_ack_sent;
                            ack_msg.header.rwnd = ktp_sockets[i].rwnd.size;
                            
                            printf("Socket %d: Sending ACK for duplicate packet, last_ack=%d\n", 
                                   i, ack_msg.header.last_ack);
                            
                            sendto(ktp_sockets[i].udp_sockfd, &ack_msg, sizeof(ack_msg.header), 0,
                                   (struct sockaddr*)&ktp_sockets[i].dst_addr, 
                                   sizeof(struct sockaddr_in));
                        }
                        else if (in_window) {
                            // Check if buffer has space
                            if (ktp_sockets[i].rwnd.buffer_occupied >= RECV_BUFSIZE) {
                                // Buffer full, set nospace flag
                                ktp_sockets[i].rwnd.nospace_flag = 1;
                                ktp_sockets[i].rwnd.size = 0;
                                
                                printf("Socket %d: Buffer full, discarding packet seq=%d\n", i, seq_num);
                                pthread_mutex_unlock(&ktp_sockets[i].mutex);
                                continue;
                            }
                            
                            // Store packet in receive buffer
                            int write_pos = ktp_sockets[i].rwnd.buffer_write_pos;
                            
                            // Calculate position based on sequence number offset
                            int offset = ((seq_num - expected_seq_num + 256) % 256) % RECV_BUFSIZE;
                            int target_pos = (write_pos + offset) % RECV_BUFSIZE;
                            
                            memcpy(ktp_sockets[i].recv_buffer[target_pos], message.data, MSG_SIZE);
                            
                            // Mark this sequence number as received
                            ktp_sockets[i].rwnd.received_msgs[target_pos] = seq_num;
                            
                            // Advance expected sequence number if we received in-order packet
                            while (ktp_sockets[i].rwnd.received_msgs[ktp_sockets[i].rwnd.buffer_write_pos] 
                                   == ktp_sockets[i].rwnd.expected_seq_num) {
                                ktp_sockets[i].rwnd.expected_seq_num = (ktp_sockets[i].rwnd.expected_seq_num + 1) % 256;
                                ktp_sockets[i].rwnd.buffer_write_pos = (ktp_sockets[i].rwnd.buffer_write_pos + 1) % RECV_BUFSIZE;
                                ktp_sockets[i].rwnd.buffer_occupied++;
                                ktp_sockets[i].rwnd.size--;
                            }
                            
                            // Update last_ack_sent
                            ktp_sockets[i].rwnd.last_ack_sent = (ktp_sockets[i].rwnd.expected_seq_num - 1 + 256) % 256;
                            
                            // Send ACK
                            ktp_message_t ack_msg;
                            memset(&ack_msg, 0, sizeof(ack_msg));
                            ack_msg.header.type = MSG_ACK;
                            ack_msg.header.last_ack = ktp_sockets[i].rwnd.last_ack_sent;
                            ack_msg.header.rwnd = ktp_sockets[i].rwnd.size;
                            
                            printf("Socket %d: Sending ACK, last_ack=%d, rwnd=%d\n", 
                                   i, ack_msg.header.last_ack, ack_msg.header.rwnd);
                            
                            sendto(ktp_sockets[i].udp_sockfd, &ack_msg, sizeof(ack_msg.header), 0,
                                   (struct sockaddr*)&ktp_sockets[i].dst_addr, 
                                   sizeof(struct sockaddr_in));
                            
                            // Check if buffer now full
                            if (ktp_sockets[i].rwnd.buffer_occupied >= RECV_BUFSIZE) {
                                ktp_sockets[i].rwnd.nospace_flag = 1;
                                ktp_sockets[i].rwnd.size = 0;
                                printf("Socket %d: Buffer full after receiving packet seq=%d\n", i, seq_num);
                                pthread_mutex_unlock(&ktp_sockets[i].mutex);
                                continue;
                            }
                        }
                        else {
                            // Outside window, discard
                            printf("Socket %d: Discarding out-of-window packet seq=%d\n", i, seq_num);
                        }
                    }
                    else if (message.header.type == MSG_ACK) {
                        // Handle ACK message
                        printf("Socket %d: Received ACK message last_ack=%d, rwnd=%d\n", 
                               i, message.header.last_ack, message.header.rwnd);
                        
                        uint8_t last_ack = message.header.last_ack;
                        
                        // Update sender window size
                        ktp_sockets[i].swnd.size = message.header.rwnd;
                        
                        // Find position of last acked packet and process all ACKs
                        int ack_count = 0;
                        int found = 0;
                        
                        for (int j = 0; j < ktp_sockets[i].swnd.unack_cnt; j++) {
                            int idx = (ktp_sockets[i].swnd.base + j) % SEND_BUFSIZE;
                            // Calculate sequence number for this position
                            int seq = (ktp_sockets[i].swnd.seq_nums[idx] + 256) % 256;
                            
                            // Count this packet
                            ack_count++;
                            
                            // If we found the message with seq_num == last_ack
                            if (seq == last_ack) {
                                found = 1;
                                break;
                            }
                        }
                        
                        if (!found) {
                            // If we didn't find the sequence number in our window
                            printf("Socket %d: Duplicate or unexpected ACK last_ack=%d\n", i, last_ack);
                            pthread_mutex_unlock(&ktp_sockets[i].mutex);
                            continue;
                        }
                        
                        // Process ACKed messages
                        printf("Socket %d: ACKing %d messages up to seq %d\n", i, ack_count, last_ack);
                        
                        // Clear the acked messages and update window
                        for (int j = 0; j < ack_count; j++) {
                            int idx = (ktp_sockets[i].swnd.base + j) % SEND_BUFSIZE;
                            memset(ktp_sockets[i].send_buffer[idx], 0, MSG_SIZE);
                            ktp_sockets[i].send_buffer_occ[idx] = 0;
                        }
                        
                        // Update window base and unacked count
                        ktp_sockets[i].swnd.base = (ktp_sockets[i].swnd.base + ack_count) % 256;
                        ktp_sockets[i].swnd.unack_cnt -= ack_count;
                        
                        printf("Socket %d: Window slid, new base=%d, unack_cnt=%d\n", 
                               i, ktp_sockets[i].swnd.base, ktp_sockets[i].swnd.unack_cnt);
                    }
                    
                    pthread_mutex_unlock(&ktp_sockets[i].mutex);
                }
            }
        }
        
        // Check if any socket that had full buffer now has space
        for (int i = 0; i < MAX_KTP_SOCK; i++) {
            if (ktp_sockets[i].is_alloc && ktp_sockets[i].is_bound) {
                pthread_mutex_lock(&ktp_sockets[i].mutex);
                
                // Check if buffer was previously full but now has space
                if (ktp_sockets[i].rwnd.nospace_flag && 
                    ktp_sockets[i].rwnd.buffer_occupied < RECV_BUFSIZE) {
                    
                    // Buffer has space now
                    ktp_sockets[i].rwnd.nospace_flag = 0;
                    ktp_sockets[i].rwnd.size = RECV_BUFSIZE - ktp_sockets[i].rwnd.buffer_occupied;
                    
                    // Set up multiple window update ACKs
                    buffer_free_acks_needed[i] = 5; // Send 5 update ACKs to ensure delivery
                    
                    printf("Socket %d: Buffer now has space, will send window update ACKs\n", i);
                }
                
                // Send buffer-free ACKs if needed
                if (buffer_free_acks_needed[i] > 0) {
                    ktp_message_t ack_msg;
                    memset(&ack_msg, 0, sizeof(ack_msg));
                    ack_msg.header.type = MSG_ACK;
                    ack_msg.header.last_ack = ktp_sockets[i].rwnd.last_ack_sent;
                    ack_msg.header.rwnd = ktp_sockets[i].rwnd.size;
                    
                    sendto(ktp_sockets[i].udp_sockfd, &ack_msg, sizeof(ack_msg.header), 0,
                           (struct sockaddr*)&ktp_sockets[i].dst_addr, 
                           sizeof(struct sockaddr_in));
                    
                    buffer_free_acks_needed[i]--;
                    printf("Socket %d: Sent buffer-free ACK update: last_ack=%d, rwnd=%d\n", 
                           i, ack_msg.header.last_ack, ack_msg.header.rwnd);
                }
                
                pthread_mutex_unlock(&ktp_sockets[i].mutex);
            }
        }
    }
    
    printf("Receiver thread terminated (dropped: %.2f%%)\n", 
           (total_received > 0) ? (dropped * 100.0) / total_received : 0);
    return NULL;
}

void* sender_thread(void* arg) {
    printf("Sender thread started\n");
    struct timeval current_time;
    
    while (running) {
        // Process each socket
        for (int i = 0; i < MAX_KTP_SOCK; i++) {
            // Try to acquire the socket mutex
            if (pthread_mutex_trylock(&ktp_sockets[i].mutex) != 0) {
                continue;  // Skip if we can't acquire mutex
            }
            
            // Check if socket is allocated and bound
            if (!ktp_sockets[i].is_alloc || !ktp_sockets[i].is_bound) {
                pthread_mutex_unlock(&ktp_sockets[i].mutex);
                continue;
            }
            
            // Get current time
            gettimeofday(&current_time, NULL);
            
            // Check for timeouts and retransmit if needed
            int window_timeout = 0;
            
            // Check if any message has timed out
            for (int j = 0; j < ktp_sockets[i].swnd.unack_cnt; j++) {
                int window_idx = (ktp_sockets[i].swnd.base + j) % WND_MAXSIZE;
                
                // Calculate time difference in seconds
                struct timeval* send_time = &ktp_sockets[i].swnd.send_time[window_idx];
                double time_diff = (current_time.tv_sec - send_time->tv_sec) + 
                                  ((current_time.tv_usec - send_time->tv_usec) / 1000000.0);
                
                // If timeout occurred, set the window timeout flag
                if (time_diff >= T) {
                    window_timeout = 1;
                    break;
                }
            }
            
            // If any message timed out, retransmit all unacknowledged packets
            if (window_timeout) {
                printf("Socket %d: Timeout detected, retransmitting %d packets\n", 
                       i, ktp_sockets[i].swnd.unack_cnt);
                
                // Retransmit all messages in the window
                for (int j = 0; j < ktp_sockets[i].swnd.unack_cnt; j++) {
                    int window_idx = (ktp_sockets[i].swnd.base + j) % WND_MAXSIZE;
                    int seq_num = ktp_sockets[i].swnd.seq_nums[window_idx];
                    int buffer_idx = seq_num % SEND_BUFSIZE;
                    
                    // Create KTP message
                    ktp_message_t message;
                    memset(&message, 0, sizeof(message));
                    message.header.type = MSG_DATA;
                    message.header.seq_num = seq_num;
                    message.header.rwnd = ktp_sockets[i].rwnd.size;
                    message.header.last_ack = ktp_sockets[i].rwnd.last_ack_sent;
                    
                    // Copy data from send buffer
                    memcpy(message.data, ktp_sockets[i].send_buffer[buffer_idx], MSG_SIZE);
                    
                    // Send the message
                    sendto(ktp_sockets[i].udp_sockfd, &message, sizeof(message), 0,
                           (struct sockaddr*)&ktp_sockets[i].dst_addr, 
                           sizeof(struct sockaddr_in));
                    
                    // Update send time
                    gettimeofday(&ktp_sockets[i].swnd.send_time[window_idx], NULL);
                }
            }
            
            // Check for new messages to send (if window not full)
            while (ktp_sockets[i].swnd.unack_cnt < ktp_sockets[i].swnd.size) {
                int next_seq = ktp_sockets[i].swnd.next_seq_num;
                int buffer_idx = next_seq % SEND_BUFSIZE;
                
                // Check if there's data in the buffer to send
                if (ktp_sockets[i].send_buffer_occ[buffer_idx] == 0) {
                    break;  // No more data to send
                }
                
                // Create KTP message
                ktp_message_t message;
                memset(&message, 0, sizeof(message));
                message.header.type = MSG_DATA;
                message.header.seq_num = next_seq;
                message.header.rwnd = ktp_sockets[i].rwnd.size;
                message.header.last_ack = ktp_sockets[i].rwnd.last_ack_sent;
                
                // Copy data from send buffer
                memcpy(message.data, ktp_sockets[i].send_buffer[buffer_idx], MSG_SIZE);
                
                // Store sequence number in window
                int window_idx = (ktp_sockets[i].swnd.base + ktp_sockets[i].swnd.unack_cnt) % WND_MAXSIZE;
                ktp_sockets[i].swnd.seq_nums[window_idx] = next_seq;
                
                // Send the message
                sendto(ktp_sockets[i].udp_sockfd, &message, sizeof(message), 0,
                       (struct sockaddr*)&ktp_sockets[i].dst_addr, 
                       sizeof(struct sockaddr_in));
                
                printf("Socket %d: Sent new message with seq %d\n", i, next_seq);
                
                // Update send time
                gettimeofday(&ktp_sockets[i].swnd.send_time[window_idx], NULL);
                
                // Update next sequence number and unack count
                ktp_sockets[i].swnd.next_seq_num = (next_seq + 1) % 256;
                ktp_sockets[i].swnd.unack_cnt++;
            }
            
            pthread_mutex_unlock(&ktp_sockets[i].mutex);
        }
        
        // Sleep for a while before next iteration
        usleep(500000);  // 0.5 seconds
    }
    // print stats
    for(int i = 0; i < MAX_KTP_SOCK; i++){
        printf("Socket %d: %d packets sent\n", i, ktp_sockets[i].swnd.next_seq_num - 1);
    }
    
    printf("Sender thread terminated\n");
    return NULL;
}

void* garbage_collector_thread(void* arg) {
    printf("Garbage collector thread started\n");
    
    while (running) {
        // Check each socket
        for (int i = 0; i < MAX_KTP_SOCK; i++) {
            // Try to acquire the socket mutex
            if (pthread_mutex_trylock(&ktp_sockets[i].mutex) != 0) {
                continue;  // Skip if can't acquire mutex
            }
            
            // Check if socket is allocated
            if (ktp_sockets[i].is_alloc) {
                pid_t pid = ktp_sockets[i].pid;
                
                // Check if process still exists
                if (kill(pid, 0) == -1 && errno == ESRCH) {
                    // Process no longer exists
                    printf("Garbage collector: Process %d no longer exists, cleaning up socket %d\n", 
                           pid, i);
                    
                    // Reset socket
                    ktp_sockets[i].is_alloc = 0;
                    ktp_sockets[i].pid = 0;
                    ktp_sockets[i].is_bound = 0;
                    ktp_sockets[i].bind_req = 0;
                    
                    // Reset send window
                    ktp_sockets[i].swnd.size = WND_MAXSIZE;
                    ktp_sockets[i].swnd.base = 1;
                    ktp_sockets[i].swnd.next_seq_num = 1;
                    ktp_sockets[i].swnd.unack_cnt = 0;
                    
                    // Reset receive window
                    ktp_sockets[i].rwnd.size = RECV_BUFSIZE;
                    ktp_sockets[i].rwnd.expected_seq_num = 1;
                    ktp_sockets[i].rwnd.last_ack_sent = 0;
                    ktp_sockets[i].rwnd.buffer_occupied = 0;
                    ktp_sockets[i].rwnd.buffer_read_pos = 0;
                    ktp_sockets[i].rwnd.buffer_write_pos = 0;
                    ktp_sockets[i].rwnd.nospace_flag = 0;
                    
                    // Clear the send buffer
                    for (int j = 0; j < SEND_BUFSIZE; j++) {
                        memset(ktp_sockets[i].send_buffer[j], 0, MSG_SIZE);
                        ktp_sockets[i].send_buffer_occ[j] = 0;
                    }
                    
                    // Clear the receive buffer
                    for (int j = 0; j < RECV_BUFSIZE; j++) {
                        memset(ktp_sockets[i].recv_buffer[j], 0, MSG_SIZE);
                        ktp_sockets[i].rwnd.received_msgs[j] = 0;
                    }
                    
                    printf("Socket %d cleanup complete\n", i);
                }
            }
            
            pthread_mutex_unlock(&ktp_sockets[i].mutex);
        }
        
        // Sleep for a while before checking again
        sleep(2);  // Check every 2 seconds
    }
    
    printf("Garbage collector thread terminated\n");
    return NULL;
}


int main() {
    // Set up signal handlers
    signal(SIGINT, handle_sig);
    signal(SIGTERM, handle_sig);
    
    // Initialize random number generator for dropMessage
    srand(time(NULL));
    
    // Initialize shared memory
    if (init_shared_memory() != 0) {
        fprintf(stderr, "Failed to initialize shared memory\n");
        return 1;
    }
    
    // Create threads
    pthread_t r_thread, s_thread, g_thread;
    
    if (pthread_create(&r_thread, NULL, receiver_thread, NULL) != 0) {
        perror("Failed to create receiver thread");
        cleanup();
        return 1;
    }
    
    if (pthread_create(&s_thread, NULL, sender_thread, NULL) != 0) {
        perror("Failed to create sender thread");
        running = 0;
        pthread_join(r_thread, NULL);
        cleanup();
        return 1;
    }
    
    if (pthread_create(&g_thread, NULL, garbage_collector_thread, NULL) != 0) {
        perror("Failed to create garbage collector thread");
        running = 0;
        pthread_join(r_thread, NULL);
        pthread_join(s_thread, NULL);
        cleanup();
        return 1;
    }
    
    printf("KTP socket service initialized and ready\n");
    printf("Press Ctrl+C to terminate\n");
    
    // Keep the main thread running until signaled to stop
    while (running) {
        sleep(1);
    }
    
    // Wait for threads to finish
    printf("Shutting down KTP socket service...\n");
    pthread_join(r_thread, NULL);
    pthread_join(s_thread, NULL);
    pthread_join(g_thread, NULL);
    
    // Clean up resources
    cleanup();
    
    printf("KTP socket service terminated\n");
    return 0;
}