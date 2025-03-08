/**
 * KTP Protocol File Sender Application
 * 
 * Sends a file over the network using the KTP protocol
 */

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <unistd.h>
 #include <errno.h>
 #include <sys/socket.h>
 #include <netinet/in.h>
 #include <arpa/inet.h>
 #include "ksocket.h"
 
 /* Constants */
 #define APP_BUFFER_SIZE KTP_MSG_SIZE
 #define PROGRESS_INTERVAL 5     /* Print progress every N packets */
 #define PACKET_DELAY_US 1000    /* Microseconds between packet sends */
 #define BUFFER_FULL_DELAY_US 10000 /* Retry delay when buffer is full */
 #define SIZE_WAIT_TIME_US 500000  /* Wait after sending file size */
 #define TRANSFER_COMPLETE_WAIT_S 30 /* Time to wait after transfer completes */
 
 /**
  * Main entry point for file sender application
  * 
  * @param argc  Argument count
  * @param argv  Command line arguments
  * @return      Exit status (0 on success)
  */
 int main(int argc, char *argv[]) {
     /* Validate command line arguments */
     if (argc != 6) {
         fprintf(stderr, "Usage: %s <filename> <src_ip> <src_port> <dst_ip> <dst_port>\n", argv[0]);
         return EXIT_FAILURE;
     }
 
     const char *filename = argv[1];
     const char *src_ip = argv[2];
     int src_port = atoi(argv[3]);
     const char *dst_ip = argv[4];
     int dst_port = atoi(argv[5]);
 
     /* Open source file */
     FILE *file = fopen(filename, "rb");
     if (!file) {
         perror("Failed to open file");
         return EXIT_FAILURE;
     }
 
     /* Get file size */
     fseek(file, 0, SEEK_END);
     long file_size = ftell(file);
     fseek(file, 0, SEEK_SET);
     printf("File size: %ld bytes\n", file_size);
 
     /* Create KTP socket */
     int sockfd = k_socket(AF_INET, SOCK_KTP, 0);
     if (sockfd < 0) {
         perror("KTP socket creation failed");
         fclose(file);
         return EXIT_FAILURE;
     }
     printf("KTP socket created: %d\n", sockfd);
 
     /* Bind socket to addresses */
     if (k_bind(sockfd, src_ip, src_port, dst_ip, dst_port) < 0) {
         perror("KTP socket binding failed");
         k_close(sockfd);
         fclose(file);
         return EXIT_FAILURE;
     }
     printf("KTP socket bound to %s:%d -> %s:%d\n", src_ip, src_port, dst_ip, dst_port);
 
     /* Configure destination address */
     struct sockaddr_in dest_addr;
     memset(&dest_addr, 0, sizeof(dest_addr));
     dest_addr.sin_family = AF_INET;
     dest_addr.sin_port = htons(dst_port);
     if (inet_pton(AF_INET, dst_ip, &dest_addr.sin_addr) <= 0) {
         perror("Invalid destination IP address");
         k_close(sockfd);
         fclose(file);
         return EXIT_FAILURE;
     }
 
     /* Send file size as metadata first */
     char size_buffer[32];
     snprintf(size_buffer, sizeof(size_buffer), "%ld", file_size);
     
     if (k_sendto(sockfd, size_buffer, strlen(size_buffer) + 1, 0, 
                 (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
         perror("Failed to send file size metadata");
         k_close(sockfd);
         fclose(file);
         return EXIT_FAILURE;
     }
     printf("Sent file size metadata: %ld bytes\n", file_size);
     
     /* Brief pause to ensure receiver processes the file size */
     usleep(SIZE_WAIT_TIME_US);
 
     /* Transfer the file */
     char buffer[APP_BUFFER_SIZE];
     size_t total_sent = 0;
     size_t bytes_read;
     int packet_count = 0;
     int retry_count = 0;
 
     /* Main transfer loop */
     while ((bytes_read = fread(buffer, 1, APP_BUFFER_SIZE - 1, file)) > 0) {
         /* Null-terminate the buffer for safe string handling */
         buffer[bytes_read] = '\0';
         
         /* Transmission state */
         ssize_t bytes_sent = -1;
         int retry_notification_shown = 0;
         
         printf("Sending packet #%d (%ld bytes)...\n", packet_count + 1, bytes_read);
 
         /* Keep trying until packet is sent or fatal error occurs */
         while (bytes_sent < 0) {
             bytes_sent = k_sendto(sockfd, buffer, bytes_read + 1, 0, 
                          (struct sockaddr *)&dest_addr, sizeof(dest_addr));
             
             if (bytes_sent < 0) {
                 /* Handle send buffer full condition */
                 if (errno == E_KTP_NO_SPACE) {
                     retry_count++;
                     
                     /* Show notification only once per packet */
                     if (!retry_notification_shown) {
                         printf("Send buffer full, retrying (packet #%d)...\n", 
                                packet_count + 1);
                         retry_notification_shown = 1;
                     }
                     
                     /* Wait before retry */
                     usleep(BUFFER_FULL_DELAY_US);
                 } else {
                     /* Fatal error */
                     perror("Fatal error sending data");
                     break;
                 }
             }
         }
         
         /* Check for transmission failure */
         if (bytes_sent < 0) {
             fprintf(stderr, "Transmission failed, aborting transfer\n");
             break;
         }
         
         /* Update statistics */
         total_sent += bytes_sent - 1;  /* Subtract null terminator */
         packet_count++;
         
         /* Display progress at intervals */
         if (packet_count % PROGRESS_INTERVAL == 0) {
             float progress_pct = (float)total_sent / file_size * 100;
             printf("Progress: %ld/%ld bytes (%.1f%%) - %d retries\n", 
                    total_sent, file_size, progress_pct, retry_count);
         }
         
         /* Brief pause between packets to prevent buffer overflow */
         usleep(PACKET_DELAY_US);
     }
 
     /* Transfer summary */
     printf("\nFile transfer summary:\n");
     printf("  - Filename: %s\n", filename);
     printf("  - Total bytes sent: %ld/%ld\n", total_sent, file_size);
     printf("  - Packets sent: %d\n", packet_count);
     printf("  - Buffer full retries: %d\n", retry_count);
     
     /* Allow time for any in-flight packets to be delivered */
     printf("\nWaiting %d seconds to ensure all data is delivered...\n", 
            TRANSFER_COMPLETE_WAIT_S);
     sleep(TRANSFER_COMPLETE_WAIT_S);
 
     /* Cleanup resources */
     printf("Closing connection and releasing resources\n");
     k_close(sockfd);
     fclose(file);
     
     return (total_sent == file_size) ? EXIT_SUCCESS : EXIT_FAILURE;
 }