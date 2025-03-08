#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "ksocket.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BUFFER_SIZE MSG_SIZE

int main(int argc, char *argv[]) {
    if (argc != 6) {
        fprintf(stderr, "Usage: %s <output_filename> <src_ip> <src_port> <dst_ip> <dst_port>\n", argv[0]);
        return 1;
    }

    const char *filename = argv[1];
    const char *src_ip = argv[2];
    int src_port = atoi(argv[3]);
    const char *dst_ip = argv[4];
    int dst_port = atoi(argv[5]);

    // Create a KTP socket
    int sockfd = k_socket(AF_INET, SOCK_KTP, 0);
    if (sockfd < 0) {
        perror("Failed to create KTP socket");
        return 1;
    }
    printf("KTP socket created: %d\n", sockfd);

    // Bind the socket
    if (k_bind(sockfd, src_ip, src_port, dst_ip, dst_port) < 0) {
        perror("Failed to bind KTP socket");
        k_close(sockfd);
        return 1;
    }
    printf("KTP socket bound to %s:%d -> %s:%d\n", src_ip, src_port, dst_ip, dst_port);
    
    // Source address for k_recvfrom
    struct sockaddr_in src_addr;
    socklen_t addrlen = sizeof(src_addr);

    // Receive file size first
    char size_buffer[32];
    ssize_t size_bytes = k_recvfrom(sockfd, size_buffer, sizeof(size_buffer), 0,
                                  (struct sockaddr *)&src_addr, &addrlen);
    
    if (size_bytes < 0) {
        printf("Waiting for file size...\n");
        while (size_bytes < 0) {
            usleep(100000);  // 100ms
            size_bytes = k_recvfrom(sockfd, size_buffer, sizeof(size_buffer), 0,
                                  (struct sockaddr *)&src_addr, &addrlen);
            if (size_bytes < 0 && errno != ENOMESSAGE) {
                perror("Failed to receive file size");
                k_close(sockfd);
                return 1;
            }
        }
    }
    
    size_buffer[size_bytes] = '\0';  // Null terminate
    long file_size = atol(size_buffer);
    printf("Receiving file of size: %ld bytes\n", file_size);

    // Open file for writing
    FILE *file = fopen(filename, "wb");
    if (file == NULL) {
        perror("Failed to open output file");
        k_close(sockfd);
        return 1;
    }

    // Receive file contents
    char buffer[BUFFER_SIZE];
    size_t total_received = 0;
    int packet_count = 0;
    int consecutive_empty_reads = 0;
    const int MAX_EMPTY_READS = 5000;  // Timeout after 5000 consecutive empty reads

    while (total_received < file_size) {
        ssize_t bytes_received = k_recvfrom(sockfd, buffer, BUFFER_SIZE, 0,
                                          (struct sockaddr *)&src_addr, &addrlen);
        
        if (bytes_received < 0) {
            if (errno == ENOMESSAGE) {
                consecutive_empty_reads++;
                if (consecutive_empty_reads > MAX_EMPTY_READS) {
                    printf("Timeout waiting for more data. Possible transfer issue.\n");
                    printf("Received %ld/%ld bytes (%.1f%%)\n", 
                          total_received, file_size, 
                          (float)total_received / file_size * 100);
                    
                    // Ask user if they want to continue waiting or finish
                    printf("Continue waiting? (y/n): ");
                    char response;
                    scanf(" %c", &response);
                    if (response != 'y' && response != 'Y') {
                        printf("Transfer incomplete. Exiting.\n");
                        break;
                    }
                    
                    // Reset counter and continue waiting
                    consecutive_empty_reads = 0;
                }
                usleep(100000);  // Wait 100ms
                continue;
            } else {
                perror("Failed to receive data");
                break;
            }
        }
        
        // Got data, reset empty read counter
        consecutive_empty_reads = 0;
        
        // Write data to file
        fwrite(buffer, 1, bytes_received, file);
        
        total_received += bytes_received;
        packet_count++;
        
        // Print progress every 5 packets
        if (packet_count % 5 == 0) {
            printf("Progress: %ld/%ld bytes (%.1f%%)\n", 
                   total_received, file_size, 
                   (float)total_received / file_size * 100);
        }
    }

    printf("File reception complete. Received %ld bytes in %d packets.\n", total_received, packet_count);

    // Close the socket and file
    k_close(sockfd);
    fclose(file);
    
    return 0;
}