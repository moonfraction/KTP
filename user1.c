#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ksocket.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#define BUFFER_SIZE MSG_SIZE

int main(int argc, char *argv[]) {
    if (argc != 6) {
        fprintf(stderr, "Usage: %s <filename> <src_ip> <src_port> <dst_ip> <dst_port>\n", argv[0]);
        return 1;
    }

    const char *filename = argv[1];
    const char *src_ip = argv[2];
    int src_port = atoi(argv[3]);
    const char *dst_ip = argv[4];
    int dst_port = atoi(argv[5]);

    // Open the file to be sent
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        perror("Failed to open file");
        return 1;
    }

    // Get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    printf("File size: %ld bytes\n", file_size);

    // Create a KTP socket
    int sockfd = k_socket(AF_INET, SOCK_KTP, 0);
    if (sockfd < 0) {
        perror("Failed to create KTP socket");
        fclose(file);
        return 1;
    }
    printf("KTP socket created: %d\n", sockfd);

    // Bind the socket
    if (k_bind(sockfd, src_ip, src_port, dst_ip, dst_port) < 0) {
        perror("Failed to bind KTP socket");
        k_close(sockfd);
        fclose(file);
        return 1;
    }
    printf("KTP socket bound to %s:%d -> %s:%d\n", src_ip, src_port, dst_ip, dst_port);

    // Prepare destination address
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(dst_port);
    inet_pton(AF_INET, dst_ip, &dest_addr.sin_addr);

    // Send file size first so receiver knows how much data to expect
    char size_buffer[32];
    snprintf(size_buffer, sizeof(size_buffer), "%ld", file_size);
    
    if (k_sendto(sockfd, size_buffer, strlen(size_buffer), 0, 
                (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("Failed to send file size");
        k_close(sockfd);
        fclose(file);
        return 1;
    }
    printf("Sent file size: %ld bytes\n", file_size);
    
    // Give receiver time to process the file size
    sleep(1);  // Wait 1 second

    // Send the file contents
    char buffer[BUFFER_SIZE];
    size_t total_sent = 0;
    size_t bytes_read;
    int packet_count = 0;

    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
        // Keep trying to send the current buffer until successful
        ssize_t bytes_sent = -1;
        int retry_count = 0;
        
        while (bytes_sent < 0 && retry_count < 100) {
            bytes_sent = k_sendto(sockfd, buffer, bytes_read, 0, 
                        (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            
            if (bytes_sent < 0) {
                // Check for ENOSPACE error and retry
                if (errno == ENOSPACE) {
                    if (retry_count == 0) {
                        printf("Send buffer full, waiting...\n");
                    }
                    usleep(100000);  // Wait 100ms
                    retry_count++;
                } else {
                    perror("Failed to send data");
                    k_close(sockfd);
                    fclose(file);
                    return 1;
                }
            }
        }
        
        // If we couldn't send after multiple retries
        if (bytes_sent < 0) {
            fprintf(stderr, "Failed to send data after multiple attempts\n");
            k_close(sockfd);
            fclose(file);
            return 1;
        }
        
        total_sent += bytes_sent;
        packet_count++;
        
        // Print progress every 10 packets
        if (packet_count % 10 == 0) {
            printf("Progress: %ld/%ld bytes (%.1f%%)\n", 
                  total_sent, file_size, 
                  (float)total_sent / file_size * 100);
        }
        
        // Throttle sending rate to avoid overwhelming the buffer
        usleep(10000);  // 10ms delay
    }

    printf("File transfer complete. Sent %ld bytes in %d packets.\n", 
           total_sent, packet_count);

    // Wait to ensure all data is transmitted
    printf("Waiting to ensure all data is delivered...\n");
    sleep(10);  // Wait 10 seconds

    // Close resources
    k_close(sockfd);
    fclose(file);
    
    return 0;
}