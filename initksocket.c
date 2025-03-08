/**
 * KTP Protocol Daemon Implementation
 * 
 * Main process that manages the protocol operation through multiple threads
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
 #define COLOR_RED     "\033[0;31m"
 #define COLOR_BLUE    "\033[0;36m"
 #define COLOR_YELLOW  "\033[0;33m"
 #define COLOR_RESET   "\033[0m"
 
 /* Global state variables */
 static int running               = 1;  /* Flag controlling thread execution */
 static int shmid                 = -1; /* Shared memory ID */
 static ktp_socket_t* ktp_sockets = NULL; /* Socket array in shared memory */
 
 /* Thread function prototypes */
 void* receiver_thread(void* arg);
 void* sender_thread(void* arg);
 void* garbage_collector_thread(void* arg);
 
 /**
  * Signal handler for graceful shutdown
  * 
  * @param sig Signal number received
  */
 void handle_signal(int sig) {
     printf("KTP: Received signal %d, initiating shutdown...\n", sig);
     running = 0;
 }
 
 /**
  * Initialize shared memory segment for KTP sockets
  * 
  * @return 0 on success, -1 on failure
  */
 int init_shared_memory() {
     /* Generate key for shared memory segment */
     key_t key = ftok("/tmp", 'K');
     if (key == -1) {
         perror("KTP: ftok failed");
         return -1;
     }
     
     /* Create shared memory segment */
     shmid = shmget(key, sizeof(ktp_socket_t) * KTP_MAX_SOCKETS, IPC_CREAT | 0666);
     if (shmid == -1) {
         perror("KTP: shmget failed");
         return -1;
     }
     
     /* Attach to the shared memory segment */
     ktp_sockets = (ktp_socket_t*)shmat(shmid, NULL, 0);
     if (ktp_sockets == (void*)-1) {
         perror("KTP: shmat failed");
         return -1;
     }
     
     /* Initialize the shared memory */
     for (int i = 0; i < KTP_MAX_SOCKETS; i++) {
         /* Zero out the socket structure */
         memset(&ktp_sockets[i], 0, sizeof(ktp_socket_t));
         
         /* Create a UDP socket for this slot */
         int udp_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
         if (udp_sockfd < 0) {
             perror("KTP: Failed to create UDP socket");
             continue;  /* Skip this slot if socket creation fails */
         }
         
         /* Store socket descriptor and mark as available */
         ktp_sockets[i].udp_sockfd = udp_sockfd;
         ktp_sockets[i].is_allocated = 0;
         
         /* Initialize mutex with process-shared attribute */
         pthread_mutexattr_t attr;
         pthread_mutexattr_init(&attr);
         pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
         pthread_mutex_init(&ktp_sockets[i].socket_mutex, &attr);
         pthread_mutexattr_destroy(&attr);
         
         printf("KTP: Pre-created UDP socket %d with fd %d\n", i, udp_sockfd);
     }
     
     printf("KTP: Shared memory initialized for %d sockets\n", KTP_MAX_SOCKETS);
     return 0;
 }
 
 /**
  * Release allocated resources
  */
 void cleanup() {
     if (ktp_sockets != NULL && ktp_sockets != (void*)-1) {
         /* Detach from shared memory */
         shmdt(ktp_sockets);
     }
     
     if (shmid != -1) {
         /* Remove shared memory segment */
         shmctl(shmid, IPC_RMID, NULL);
     }
     
     printf("KTP: Resources cleaned up\n");
 }
 
 /**
  * Main entry point for the KTP daemon
  */
 int main() {
     /* Set up signal handlers for graceful termination */
     signal(SIGINT, handle_signal);
     signal(SIGTERM, handle_signal);
     
     /* Initialize random number generator for packet loss simulation */
     srand(time(NULL));
     
     /* Initialize shared memory */
     if (init_shared_memory() != 0) {
         fprintf(stderr, "KTP: Failed to initialize shared memory\n");
         return 1;
     }
     
     /* Thread handles */
     pthread_t r_thread, s_thread, g_thread;
     
     /* Start the receiver thread (R) */
     if (pthread_create(&r_thread, NULL, receiver_thread, NULL) != 0) {
         perror("KTP: Failed to create receiver thread");
         cleanup();
         return 1;
     }
     
     /* Start the sender thread (S) */
     if (pthread_create(&s_thread, NULL, sender_thread, NULL) != 0) {
         perror("KTP: Failed to create sender thread");
         running = 0;  /* Signal other threads to terminate */
         pthread_join(r_thread, NULL);
         cleanup();
         return 1;
     }
     
     /* Start the garbage collector thread (G) */
     if (pthread_create(&g_thread, NULL, garbage_collector_thread, NULL) != 0) {
         perror("KTP: Failed to create garbage collector thread");
         running = 0;  /* Signal other threads to terminate */
         pthread_join(r_thread, NULL);
         pthread_join(s_thread, NULL);
         cleanup();
         return 1;
     }
     
     printf("KTP: Protocol daemon initialized. All threads started.\n");
     
     /* Keep main thread running until signaled to stop */
     while (running) {
         sleep(1);
     }
     
     /* Wait for all threads to terminate */
     printf("KTP: Waiting for threads to finish...\n");
     pthread_join(r_thread, NULL);
     pthread_join(s_thread, NULL);
     pthread_join(g_thread, NULL);
     
     /* Perform final cleanup */
     cleanup();
     
     printf("KTP: Protocol daemon terminated\n");
     return 0;
 }
 
 /**
  * Receiver thread (R) - Processes incoming packets and sends acknowledgments
  * 
  * @param arg Thread argument (unused)
  * @return Always NULL
  */
 void* receiver_thread(void* arg) {
     printf(COLOR_RESET "KTP Receiver thread (R) started\n");
 
     int total_received = 0;
     int dropped = 0;
     
     fd_set read_fds;
     struct timeval tv;
     
     /* Track buffer-free notifications needed per socket */
     int buffer_free_acks_needed[KTP_MAX_SOCKETS];
     for (int i = 0; i < KTP_MAX_SOCKETS; i++) {
         buffer_free_acks_needed[i] = 0;
     }
 
     /* Main thread loop */
     while (running) {
         /* Process binding requests from client applications */
         for (int i = 0; i < KTP_MAX_SOCKETS; i++) {
             if (pthread_mutex_trylock(&ktp_sockets[i].socket_mutex) == 0) {
                 const int is_binding_pending = 
                     ktp_sockets[i].is_allocated && 
                     ktp_sockets[i].bind_requested && 
                     !ktp_sockets[i].is_bound;
                     
                 if (is_binding_pending) {
                     printf(COLOR_YELLOW "KTP: Processing bind request for socket %d\n", i);
                     
                     /* Close and recreate UDP socket to ensure clean state */
                     close(ktp_sockets[i].udp_sockfd);
                     ktp_sockets[i].udp_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
                     
                     /* Bind the socket to the requested address */
                     if (bind(ktp_sockets[i].udp_sockfd, 
                             (struct sockaddr*)&ktp_sockets[i].src_addr, 
                             sizeof(struct sockaddr_in)) < 0) {
                         perror("KTP: Binding UDP socket failed");
                         /* Don't set is_bound - client will time out */
                     } else {
                         /* Binding successful */
                         ktp_sockets[i].is_bound = 1;
                         ktp_sockets[i].bind_requested = 0;
                         printf(COLOR_YELLOW "KTP: Socket %d bound successfully\n", i);
                     }
                 }
                 pthread_mutex_unlock(&ktp_sockets[i].socket_mutex);
             }
         }
         
         /* Set up file descriptor set for select() */
         FD_ZERO(&read_fds);
         int max_fd = -1;
         
         /* Add all active UDP sockets to the set */
         for (int i = 0; i < KTP_MAX_SOCKETS; i++) {
             if (pthread_mutex_trylock(&ktp_sockets[i].socket_mutex) == 0) {
                 const int is_socket_active = 
                     ktp_sockets[i].is_allocated && 
                     ktp_sockets[i].is_bound && 
                     ktp_sockets[i].udp_sockfd >= 0;
                     
                 if (is_socket_active) {
                     int fd = ktp_sockets[i].udp_sockfd;
                     
                     /* Validate socket descriptor */
                     int error = 0;
                     socklen_t len = sizeof(error);
                     int retval = getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len);
                     
                     if (retval == 0 && error == 0) {
                         /* Socket is valid, add to select set */
                         FD_SET(fd, &read_fds);
                         if (fd > max_fd) {
                             max_fd = fd;
                         }
                     } else {
                         printf(COLOR_YELLOW "KTP: Socket %d: Invalid fd %d (retval=%d, error=%d)\n", 
                                i, fd, retval, error);
                         /* Socket appears invalid but marked as allocated - fix this */
                         ktp_sockets[i].is_allocated = 0;
                         ktp_sockets[i].udp_sockfd = -1;
                     }
                 }
                 pthread_mutex_unlock(&ktp_sockets[i].socket_mutex);
             }
         }
         
         /* If no active sockets, just wait a bit and try again */
         if (max_fd < 0) {
             usleep(100000); /* 100ms */
             continue;
         }
         
         /* Set timeout for select */
         tv.tv_sec = 1;  /* 1 second */
         tv.tv_usec = 0;
         
         /* Wait for incoming data on any socket */
         int select_result = select(max_fd + 1, &read_fds, NULL, NULL, &tv);
         
         if (select_result < 0) {
             /* Handle select error */
             if (running) { /* Only log if we're not shutting down */
                 perror("KTP: select error");
             }
             continue;
         }
         
         /* Process each socket that has data available */
         for (int i = 0; i < KTP_MAX_SOCKETS; i++) {
             if (pthread_mutex_trylock(&ktp_sockets[i].socket_mutex) == 0) {
                 if (ktp_sockets[i].is_allocated && ktp_sockets[i].is_bound) {
                     int fd = ktp_sockets[i].udp_sockfd;
                     
                     if (FD_ISSET(fd, &read_fds)) {
                         /* Receive incoming message */
                         ktp_message_t message;
                         struct sockaddr_in src_addr;
                         socklen_t src_addr_len = sizeof(src_addr);
                         
                         ssize_t bytes_received = recvfrom(fd, &message, sizeof(message), 0,
                                                          (struct sockaddr *)&src_addr, &src_addr_len);
 
                         total_received++;
                         
                         /* Check for simulated packet loss */
                         if (dropMessage(KTP_PACKET_LOSS_PROB)) {
                             printf(COLOR_RED "KTP: Socket %d: Dropped received message (simulated loss)\n", i);
                             dropped++;
                             pthread_mutex_unlock(&ktp_sockets[i].socket_mutex);
                             continue;
                         }
                         
                         /* Handle receive errors */
                         if (bytes_received <= 0) {
                             pthread_mutex_unlock(&ktp_sockets[i].socket_mutex);
                             continue;
                         }
                         
                         /* Process message based on type */
                         if (message.header.type == KTP_TYPE_DATA) {
                             /* Reset buffer free notification counter */
                             buffer_free_acks_needed[i] = 0;
                             
                             /* Log received data message */
                             printf(COLOR_YELLOW "KTP: Socket %d: Received DATA message seq=%d\n", 
                                    i, message.header.seq_num);
                             
                             const uint8_t seq_num = message.header.seq_num;
                             const uint8_t expected_seq_num = ktp_sockets[i].rwnd.expected_seq_num;
                             
                             /* Check for duplicate message */
                             int is_duplicate = 0;
                             for (int j = 0; j < KTP_RECV_BUFFER_SIZE; j++) {
                                 if (ktp_sockets[i].rwnd.received_msgs[j] == seq_num) {
                                     is_duplicate = 1;
                                     break;
                                 }
                             }
                             
                             /* Calculate acceptable sequence number range (window) */
                             int in_window = 0;
                             const int window_end = (expected_seq_num + ktp_sockets[i].rwnd.size - 1) % 256;
                             
                             /* Check if sequence number is within window */
                             if (expected_seq_num <= window_end) {
                                 /* Normal case (window doesn't wrap) */
                                 in_window = (seq_num >= expected_seq_num && seq_num <= window_end);
                             } else {
                                 /* Window wraps around (crosses 255->0) */
                                 in_window = (seq_num >= expected_seq_num || seq_num <= window_end);
                             }
                             
                             if (is_duplicate) {
                                 /* For duplicate packets, just send ACK with current state */
                                 ktp_message_t ack_msg;
                                 memset(&ack_msg, 0, sizeof(ack_msg));
                                 ack_msg.header.type = KTP_TYPE_ACK;
                                 ack_msg.header.last_ack = ktp_sockets[i].rwnd.last_ack_sent;
                                 ack_msg.header.rwnd = ktp_sockets[i].rwnd.size;
                                 
                                 printf(COLOR_YELLOW "KTP: Socket %d: Sending ACK for duplicate packet, last_ack=%d\n", 
                                        i, ack_msg.header.last_ack);
                                 
                                 sendto(ktp_sockets[i].udp_sockfd, &ack_msg, sizeof(ack_msg.header), 0,
                                         (struct sockaddr *)&ktp_sockets[i].dst_addr, 
                                         sizeof(struct sockaddr_in));
                             }
                             else if (in_window) {
                                 /* Packet is within receive window - process it */
                                 
                                 /* Check if buffer has space */
                                 if (ktp_sockets[i].rwnd.buffer_occupied >= KTP_RECV_BUFFER_SIZE) {
                                     /* Buffer full - set flag and drop packet */
                                     ktp_sockets[i].rwnd.nospace_flag = 1;
                                     ktp_sockets[i].rwnd.size = 0;
                                     
                                     printf(COLOR_YELLOW "KTP: Socket %d: Buffer full, discarding packet seq=%d\n", 
                                           i, seq_num);
                                     pthread_mutex_unlock(&ktp_sockets[i].socket_mutex);
                                     continue;
                                 }
                                 
                                 /* Store packet in receive buffer at calculated position */
                                 const int write_pos = ktp_sockets[i].rwnd.buffer_write_pos;
                                 const int offset = ((seq_num - expected_seq_num + 256) % 256) % KTP_RECV_BUFFER_SIZE;
                                 const int target_pos = (write_pos + offset) % KTP_RECV_BUFFER_SIZE;
 
                                 /* Copy message data to buffer */
                                 memcpy(ktp_sockets[i].recv_buffer[target_pos], message.data, KTP_MSG_SIZE);
                                 
                                 /* Mark sequence number as received */
                                 ktp_sockets[i].rwnd.received_msgs[target_pos] = seq_num;
                                 
                                 /* Advance expected sequence number for in-order packets */
                                 while (ktp_sockets[i].rwnd.received_msgs[ktp_sockets[i].rwnd.buffer_write_pos] == 
                                       ktp_sockets[i].rwnd.expected_seq_num) {
                                     /* Update state for each in-order packet */
                                     ktp_sockets[i].rwnd.expected_seq_num = 
                                         (ktp_sockets[i].rwnd.expected_seq_num + 1) % 256;
                                     ktp_sockets[i].rwnd.buffer_write_pos = 
                                         (ktp_sockets[i].rwnd.buffer_write_pos + 1) % KTP_RECV_BUFFER_SIZE;
                                     ktp_sockets[i].rwnd.buffer_occupied++;
                                     ktp_sockets[i].rwnd.size--;
                                 }
                                 
                                 /* Update last_ack_sent */
                                 ktp_sockets[i].rwnd.last_ack_sent = (ktp_sockets[i].rwnd.expected_seq_num - 1 + 256) % 256;
                                 
                                 /* Send ACK with updated state */
                                 ktp_message_t ack_msg;
                                 memset(&ack_msg, 0, sizeof(ack_msg));
                                 ack_msg.header.type = KTP_TYPE_ACK;
                                 ack_msg.header.last_ack = ktp_sockets[i].rwnd.last_ack_sent;
                                 ack_msg.header.rwnd = ktp_sockets[i].rwnd.size;
                                 
                                 printf(COLOR_YELLOW "KTP: Socket %d: Sending ACK, last_ack=%d, rwnd=%d\n", 
                                        i, ack_msg.header.last_ack, ack_msg.header.rwnd);
                                 
                                 sendto(ktp_sockets[i].udp_sockfd, &ack_msg, sizeof(ack_msg.header), 0,
                                       (struct sockaddr *)&ktp_sockets[i].dst_addr, 
                                       sizeof(struct sockaddr_in));
 
                                 /* Check if buffer is now full */
                                 if (ktp_sockets[i].rwnd.buffer_occupied >= KTP_RECV_BUFFER_SIZE) {
                                     ktp_sockets[i].rwnd.nospace_flag = 1;
                                     ktp_sockets[i].rwnd.size = 0;
                                     
                                     printf(COLOR_YELLOW "KTP: Socket %d: Buffer full after receiving packet seq=%d\n", 
                                           i, seq_num);
                                 }
                             } 
                             else {
                                 /* Sequence number outside window - discard */
                                 printf(COLOR_YELLOW "KTP: Socket %d: Discarding out-of-window packet seq=%d\n", 
                                       i, seq_num);
                             }
                         }
                         else if (message.header.type == KTP_TYPE_ACK) {
                             /* Handle ACK message */
                             printf(COLOR_YELLOW "KTP: Socket %d: Received ACK message last_ack=%d, rwnd=%d\n", 
                                    i, message.header.last_ack, message.header.rwnd);
                             
                             const uint8_t last_ack = message.header.last_ack;
                             
                             /* Update send window size based on advertised receive window */
                             ktp_sockets[i].swnd.size = message.header.rwnd;
                             
                             /* Process acknowledged packets */
                             int acked_count = 0;
                             int found_ack = 0;
                             
                             /* Count acknowledged packets up to last_ack */
                             for (int j = 0; j < ktp_sockets[i].swnd.num_unacked; j++) {
                                 int window_idx = (ktp_sockets[i].swnd.base + j) % KTP_MAX_WINDOW_SIZE;
                                 uint8_t seq_num = ktp_sockets[i].swnd.seq_nums[window_idx];
                                 
                                 acked_count++;
                                 
                                 /* Check if we found the ack boundary */
                                 if (seq_num == last_ack) {
                                     found_ack = 1;
                                     break;
                                 }
                             }
                             
                             /* If we didn't find the ack in our window, it's a duplicate */
                             if (!found_ack) {
                                 printf(COLOR_YELLOW "KTP: Socket %d: Duplicate ACK last_ack=%d, updating window size only\n", 
                                       i, last_ack);
                                 pthread_mutex_unlock(&ktp_sockets[i].socket_mutex);
                                 continue;
                             }
                             
                             /* Found valid ACK, process acknowledged packets */
                             printf(COLOR_YELLOW "KTP: Socket %d: ACKing %d messages up to seq %d\n", 
                                   i, acked_count, last_ack);
                             
                             /* Clear the acknowledged messages from buffer */
                             for (int j = 0; j < acked_count; j++) {
                                 int seq_idx = (ktp_sockets[i].swnd.base + j) % KTP_SEND_BUFFER_SIZE;
                                 
                                 /* Clear buffer and mark as unoccupied */
                                 memset(ktp_sockets[i].send_buffer[seq_idx], 0, KTP_MSG_SIZE);
                                 ktp_sockets[i].send_buffer_occ[seq_idx] = 0;
                             }
                             
                             /* Slide window forward */
                             ktp_sockets[i].swnd.base = (ktp_sockets[i].swnd.base + acked_count) % KTP_MAX_WINDOW_SIZE;
                             ktp_sockets[i].swnd.num_unacked -= acked_count;
                             
                             printf(COLOR_YELLOW "KTP: Socket %d: Window slid, new base=%d, num_unacked=%d\n", 
                                    i, ktp_sockets[i].swnd.base, ktp_sockets[i].swnd.num_unacked);
                         }
                     }
                 }
                 pthread_mutex_unlock(&ktp_sockets[i].socket_mutex);
             }
         }
         
         /* Handle buffer space availability notifications */
         for (int i = 0; i < KTP_MAX_SOCKETS; i++) {
             if (pthread_mutex_trylock(&ktp_sockets[i].socket_mutex) == 0) {
                 if (ktp_sockets[i].is_allocated && ktp_sockets[i].is_bound) {
                     /* Check if buffer was previously full but now has space */
                     const int buffer_freed = 
                         ktp_sockets[i].rwnd.nospace_flag && 
                         ktp_sockets[i].rwnd.buffer_occupied < KTP_RECV_BUFFER_SIZE;
                         
                     if (buffer_freed) {
                         /* Buffer has transitioned from full to having space */
                         ktp_sockets[i].rwnd.nospace_flag = 0;
                         
                         /* Schedule multiple window update ACKs to ensure delivery */
                         buffer_free_acks_needed[i] = 10;
                         
                         printf(COLOR_YELLOW "KTP: Socket %d: Buffer now has space, will send 10 window update ACKs\n", i);
                     }
                     
                     /* Send any scheduled buffer-free notification ACKs */
                     if (buffer_free_acks_needed[i] > 0) {
                         ktp_message_t ack_msg;
                         memset(&ack_msg, 0, sizeof(ack_msg));
                         ack_msg.header.type = KTP_TYPE_ACK;
                         ack_msg.header.last_ack = ktp_sockets[i].rwnd.last_ack_sent;
                         ack_msg.header.rwnd = ktp_sockets[i].rwnd.size;
                         
                         printf(COLOR_YELLOW "KTP: Socket %d: Sending buffer-free ACK %d/10: last_ack=%d, rwnd=%d\n", 
                             i, 11 - buffer_free_acks_needed[i], 
                             ack_msg.header.last_ack, ack_msg.header.rwnd);
                         
                         sendto(ktp_sockets[i].udp_sockfd, &ack_msg, sizeof(ack_msg.header), 0,
                             (struct sockaddr *)&ktp_sockets[i].dst_addr, 
                             sizeof(struct sockaddr_in));
                         
                         buffer_free_acks_needed[i]--;
                     }
                 }
                 pthread_mutex_unlock(&ktp_sockets[i].socket_mutex);
             }
         }
     }
     
     /* Print packet loss statistics before exiting */
     if (total_received > 0) {
         printf(COLOR_RESET "KTP: Packet statistics: %d received, %d dropped (%.2f%%)\n", 
                total_received, dropped, (dropped * 100.0) / total_received);
     }
     printf(COLOR_RESET "KTP Receiver thread (R) terminated\n");
     return NULL;
 }
 
 /**
  * Sender thread (S) - Transmits new packets and handles retransmissions
  * 
  * @param arg Thread argument (unused)
  * @return Always NULL
  */
 void* sender_thread(void* arg) {
     printf(COLOR_RESET "KTP Sender thread (S) started\n");
     struct timeval current_time;
 
     /* Track transmission statistics per socket */
     int transmission_per_socket[KTP_MAX_SOCKETS];
     for (int i = 0; i < KTP_MAX_SOCKETS; i++) {
         transmission_per_socket[i] = 0;
     }
     
     /* Main thread loop */
     while (running) {
         /* Process each socket */
         for (int i = 0; i < KTP_MAX_SOCKETS; i++) {
             /* Skip if we can't lock the mutex (socket in use by another thread) */
             if (pthread_mutex_trylock(&ktp_sockets[i].socket_mutex) != 0) {
                 continue;
             }
             
             /* Process only allocated and bound sockets */
             const int is_active = ktp_sockets[i].is_allocated && ktp_sockets[i].is_bound;
             if (!is_active) {
                 pthread_mutex_unlock(&ktp_sockets[i].socket_mutex);
                 continue;
             }
             
             /* Get current time for timeout calculations */
             gettimeofday(&current_time, NULL);
             
             /* Check for timeouts and retransmit if needed */
             int window_timeout = 0;
 
             /* First pass: check if any message has timed out */
             for (int j = 0; j < ktp_sockets[i].swnd.num_unacked; j++) {
                 /* Calculate index in circular buffer */
                 int window_idx = (ktp_sockets[i].swnd.base + j) % KTP_MAX_WINDOW_SIZE;
                 
                 /* Calculate elapsed time since last transmission */
                 long time_diff_sec = current_time.tv_sec - ktp_sockets[i].swnd.send_times[window_idx].tv_sec;
                 long time_diff_usec = current_time.tv_usec - ktp_sockets[i].swnd.send_times[window_idx].tv_usec;
                 double time_diff = time_diff_sec + (time_diff_usec / 1000000.0);
                 
                 /* Check against timeout threshold */
                 if (time_diff >= KTP_TIMEOUT_SEC) {
                     window_timeout = 1;
                     break;  /* One timeout is enough to trigger retransmission */
                 }
             }
 
             /* If any message timed out, retransmit the entire window */
             if (window_timeout) {
                 printf(COLOR_BLUE "KTP: Socket %d: Window timeout detected, retransmitting all %d unacked messages\n", 
                        i, ktp_sockets[i].swnd.num_unacked);
                 
                 /* Retransmit all messages in the current window */
                 for (int j = 0; j < ktp_sockets[i].swnd.num_unacked; j++) {
                    /* Calculate indices for circular buffers */
                    int window_idx = (ktp_sockets[i].swnd.base + j) % KTP_MAX_WINDOW_SIZE;
                    int seq_num = ktp_sockets[i].swnd.seq_nums[window_idx];
                    int seq_idx = (ktp_sockets[i].swnd.base + j) % KTP_SEND_BUFFER_SIZE;
                    
                    /* Create KTP message for retransmission */
                    ktp_message_t message;
                    message.header.type = KTP_TYPE_DATA;
                    message.header.seq_num = seq_num;
                    message.header.rwnd = ktp_sockets[i].rwnd.size;
                    message.header.last_ack = ktp_sockets[i].rwnd.expected_seq_num - 1;
                    
                    /* Copy data from send buffer */
                    memcpy(message.data, ktp_sockets[i].send_buffer[seq_idx], 
                           KTP_MSG_SIZE);
                    
                    /* Send the message */
                    sendto(ktp_sockets[i].udp_sockfd, &message, sizeof(message), 0,
                            (struct sockaddr *)&ktp_sockets[i].dst_addr, 
                            sizeof(struct sockaddr_in));
                        
                    /* Update statistics */
                    transmission_per_socket[i]++;
                    
                    /* Update send timestamp for timeout calculation */
                    gettimeofday(&ktp_sockets[i].swnd.send_times[window_idx], NULL);
                }
            }
            
            /* Process new messages to send if window not full */
            while (ktp_sockets[i].swnd.num_unacked < ktp_sockets[i].swnd.size) {
                /* Calculate next sequence index in buffer */
                int next_seq_idx = (ktp_sockets[i].swnd.base + ktp_sockets[i].swnd.num_unacked) % KTP_SEND_BUFFER_SIZE;
                
                /* Check if there's a message ready to send */
                if (ktp_sockets[i].send_buffer_occ[next_seq_idx] == 0) {
                    /* No more messages queued for sending */
                    break;
                }
                
                /* Create KTP message */
                ktp_message_t message;
                message.header.type = KTP_TYPE_DATA;
                message.header.seq_num = ktp_sockets[i].swnd.next_seq_num;
                message.header.rwnd = ktp_sockets[i].rwnd.size;
                message.header.last_ack = ktp_sockets[i].rwnd.expected_seq_num - 1;
                
                /* Copy data from send buffer */
                memcpy(message.data, ktp_sockets[i].send_buffer[next_seq_idx], 
                       KTP_MSG_SIZE);
                
                /* Store sequence number in window tracking */
                int window_idx = (ktp_sockets[i].swnd.base + ktp_sockets[i].swnd.num_unacked) % KTP_MAX_WINDOW_SIZE;
                ktp_sockets[i].swnd.seq_nums[window_idx] = message.header.seq_num;
                
                /* Record send time for timeout calculation */
                gettimeofday(&ktp_sockets[i].swnd.send_times[window_idx], NULL);
                
                /* Send the message */
                sendto(ktp_sockets[i].udp_sockfd, &message, sizeof(message), 0,
                        (struct sockaddr *)&ktp_sockets[i].dst_addr, 
                        sizeof(struct sockaddr_in));
                
                /* Update statistics */
                transmission_per_socket[i]++;
                
                printf(COLOR_BLUE "KTP: Socket %d: Sent new message with seq %d\n", 
                       i, message.header.seq_num);
                
                /* Update window state */
                ktp_sockets[i].swnd.next_seq_num = (ktp_sockets[i].swnd.next_seq_num + 1) % 256;
                ktp_sockets[i].swnd.num_unacked++;
            }
            
            pthread_mutex_unlock(&ktp_sockets[i].socket_mutex);
        }
        
        /* Sleep for half the timeout period before next iteration */
        usleep(KTP_TIMEOUT_SEC * 1000000 / 2);
    }

    /* Print transmission statistics before exiting */
    for (int i = 0; i < KTP_MAX_SOCKETS; i++) {
        if (transmission_per_socket[i] > 0) {
            printf(COLOR_RESET "KTP: Socket %d: Transmitted %d messages\n", 
                   i, transmission_per_socket[i]);
        }
    }
    
    printf(COLOR_RESET "KTP Sender thread (S) terminated\n");
    return NULL;
}

/**
 * Garbage collector thread (G) - Cleans up resources for terminated processes
 * 
 * @param arg Thread argument (unused)
 * @return Always NULL
 */
void* garbage_collector_thread(void* arg) {
    printf(COLOR_RESET "KTP Garbage collector thread (G) started\n");
    
    /* Constants */
    const int CHECK_INTERVAL_SEC = 5; /* Time between cleanup cycles */
    
    /* Main thread loop */
    while (running) {
        /* Check each socket */
        for (int i = 0; i < KTP_MAX_SOCKETS; i++) {
            /* Try to lock the socket mutex */
            if (pthread_mutex_trylock(&ktp_sockets[i].socket_mutex) == 0) {
                /* Check only allocated sockets */
                if (ktp_sockets[i].is_allocated) {
                    pid_t pid = ktp_sockets[i].pid;
                    
                    /* Check if the process is still running */
                    if (kill(pid, 0) == -1) {
                        /* Process is no longer running - clean up the socket */
                        printf(COLOR_RED "KTP: Garbage collector: Process %d no longer running, cleaning up socket %d\n", 
                               pid, i);
                        
                        /* Release the socket */
                        ktp_sockets[i].is_allocated = 0;
                        ktp_sockets[i].pid = 0;
                        ktp_sockets[i].is_bound = 0;
                        
                        /* Clear send buffer */
                        for (int j = 0; j < KTP_SEND_BUFFER_SIZE; j++) {
                            memset(ktp_sockets[i].send_buffer[j], 0, KTP_MSG_SIZE);
                            ktp_sockets[i].send_buffer_occ[j] = 0;
                        }
                        
                        /* Clear receive buffer */
                        for (int j = 0; j < KTP_RECV_BUFFER_SIZE; j++) {
                            memset(ktp_sockets[i].recv_buffer[j], 0, KTP_MSG_SIZE);
                        }
                        
                        /* Reset tracking arrays */
                        memset(ktp_sockets[i].rwnd.received_msgs, 0, sizeof(ktp_sockets[i].rwnd.received_msgs));
                        
                        /* Clear window structures */
                        memset(&ktp_sockets[i].swnd, 0, sizeof(ktp_sockets[i].swnd));
                        memset(&ktp_sockets[i].rwnd, 0, sizeof(ktp_sockets[i].rwnd));
                    }
                }
                /* Unlock the mutex */
                pthread_mutex_unlock(&ktp_sockets[i].socket_mutex);
            }
            /* If mutex is locked, skip this socket for now */
        }
        
        /* Sleep before next cleanup cycle */
        sleep(CHECK_INTERVAL_SEC);
    }
    
    printf(COLOR_RESET "KTP Garbage collector thread (G) terminated\n");
    return NULL;
}