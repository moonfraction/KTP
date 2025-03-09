// KTP Protocol File Sender Application
// Sends a file over the network using the KTP protocol

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ksocket.h"

// CONFIG SECTION
#define APP_BUFFER_SIZE KTP_MSG_SIZE
#define PROGRESS_INTERVAL 5     // Print progress every N packets
#define PACKET_DELAY_US 1000    // Microseconds between packet sends
#define BUFFER_FULL_DELAY_US 10000 // Retry delay when buffer is full
#define SIZE_WAIT_TIME_US 500000  // Wait after sending file size
#define TRANSFER_COMPLETE_WAIT_S 30 // Time to wait after transfer completes

// Forward declarations
static void display_transfer_summary(const char *filename, long total_sent, 
                                    long file_size, int packet_count, int retry_count);
static int setup_connection(int sockfd, const char *dst_ip, int dst_port, 
                           struct sockaddr_in *dest_addr);
static int transmit_file_size(int sockfd, struct sockaddr_in *dest_addr, long file_size);

/**
 * Main entry point for file sender application
 */
int main(int argc, char *argv[]) 
{
    int sockfd, packet_count = 0, retry_count = 0;
    FILE *file;
    long file_size, total_sent = 0;
    char buffer[APP_BUFFER_SIZE];
    struct sockaddr_in dest_addr;
    
    // Argument validation
    if (argc != 6) {
        fprintf(stderr, "Usage: %s <src_ip> <src_port> <dst_ip> <dst_port> <input_filename>\n", 
                argv[0]);
        return EXIT_FAILURE;
    }

    const char *src_ip = argv[1];
    int src_port = atoi(argv[2]);
    const char *dst_ip = argv[3];
    int dst_port = atoi(argv[4]);
    const char *filename = argv[5];
    
    // Initialize resources
    if (!(file = fopen(filename, "rb"))) {
        perror("Failed to open file");
        return EXIT_FAILURE;
    }

    // Determine file size
    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    rewind(file);  // Alternative to fseek(file, 0, SEEK_SET)
    printf("[INFO] Detected file size: %ld bytes\n", file_size);

    // Socket creation
    if ((sockfd = k_socket(AF_INET, SOCK_KTP, 0)) < 0) {
        perror("KTP socket creation failed");
        fclose(file);
        return EXIT_FAILURE;
    }
    printf("[SETUP] KTP socket initialized with descriptor: %d\n", sockfd);

    // Bind socket to source and destination
    if (k_bind(sockfd, src_ip, src_port, dst_ip, dst_port) < 0) {
        perror("KTP socket binding failed");
        goto cleanup_and_exit_failure;
    }
    printf("[CONFIG] Connection established: %s:%d → %s:%d\n", 
           src_ip, src_port, dst_ip, dst_port);

    // Setup destination address structure
    if (!setup_connection(sockfd, dst_ip, dst_port, &dest_addr)) {
        goto cleanup_and_exit_failure;
    }

    // Send file size as header information
    if (!transmit_file_size(sockfd, &dest_addr, file_size)) {
        goto cleanup_and_exit_failure;
    }
    
    // MAIN FILE TRANSFER LOOP
    size_t bytes_read;
    while (1) {
        // Read chunk from file
        bytes_read = fread(buffer, 1, APP_BUFFER_SIZE - 1, file);
        if (bytes_read == 0) break;  // End of file reached
        
        // Null-terminate for safety
        buffer[bytes_read] = '\0';
        
        // Transmission tracking
        ssize_t bytes_sent = -1;
        int retry_notification_shown = 0;
        
        printf("[PACKET] Sending packet #%d (%ld bytes)...\n", 
              packet_count + 1, bytes_read);

        // Transmission retry loop
        do {
            bytes_sent = k_sendto(sockfd, buffer, bytes_read + 1, 0, 
                      (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            
            if (bytes_sent < 0) {
                // Handle buffer full condition
                if (errno == E_KTP_NO_SPACE) {
                    retry_count++;
                    
                    if (!retry_notification_shown) {
                        printf("[BUFFER] Transmission buffer full - retrying packet #%d...\n", 
                              packet_count + 1);
                        retry_notification_shown = 1;
                    }
                    
                    usleep(BUFFER_FULL_DELAY_US);
                } else {
                    // Other errors
                    perror("Fatal error sending data");
                    break;  // Exit retry loop on fatal errors
                }
            }
        } while (bytes_sent < 0);
        
        // Check if transmission succeeded
        if (bytes_sent < 0) {
            fprintf(stderr, "Transmission failed, aborting transfer\n");
            break;
        }
        
        // Update progress tracking
        total_sent += bytes_sent - 1;  // Exclude null terminator
        packet_count++;
        
        // Progress reporting
        if (packet_count % PROGRESS_INTERVAL == 0) {
            float progress_pct = (float)total_sent / file_size * 100;
            printf("[STATUS] Progress: %ld/%ld bytes | %.1f%% complete | %d retries\n", 
                  total_sent, file_size, progress_pct, retry_count);
        }
        
        // Rate limiting
        usleep(PACKET_DELAY_US);
    }

    // Display final results
    display_transfer_summary(filename, total_sent, file_size, 
                           packet_count, retry_count);
    
    // Wait for delivery completion
    printf("\n[FINALIZE] Waiting %d seconds for packet delivery completion...\n", 
          TRANSFER_COMPLETE_WAIT_S);
    sleep(TRANSFER_COMPLETE_WAIT_S);

    // Resource cleanup
    printf("[CLEANUP] Closing connection and releasing system resources\n");
    k_close(sockfd);
    fclose(file);
    
    return (total_sent == file_size) ? EXIT_SUCCESS : EXIT_FAILURE;

cleanup_and_exit_failure:
    k_close(sockfd);
    fclose(file);
    return EXIT_FAILURE;
}

/**
 * Display transfer statistics and summary
 */
static void display_transfer_summary(const char *filename, long total_sent, 
                                    long file_size, int packet_count, int retry_count)
{
    printf("\n✧✧✧ FILE TRANSFER SUMMARY ✧✧✧\n");
    printf("  • Source file:      %s\n", filename);
    printf("  • Bytes transferred: %ld of %ld\n", total_sent, file_size);
    printf("  • Packets sent:     %d\n", packet_count);
    printf("  • Buffer retries:   %d\n", retry_count);
}

/**
 * Configure destination address structure
 */
static int setup_connection(int sockfd, const char *dst_ip, int dst_port, 
                           struct sockaddr_in *dest_addr)
{
    memset(dest_addr, 0, sizeof(*dest_addr));
    dest_addr->sin_family = AF_INET;
    dest_addr->sin_port = htons(dst_port);
    
    if (inet_pton(AF_INET, dst_ip, &dest_addr->sin_addr) <= 0) {
        perror("Invalid destination IP address");
        return 0;
    }
    
    return 1;
}

/**
 * Send file size information to receiver
 */
static int transmit_file_size(int sockfd, struct sockaddr_in *dest_addr, long file_size)
{
    char size_buffer[32];
    snprintf(size_buffer, sizeof(size_buffer), "%ld", file_size);
    
    if (k_sendto(sockfd, size_buffer, strlen(size_buffer) + 1, 0, 
                (struct sockaddr *)dest_addr, sizeof(*dest_addr)) < 0) {
        perror("Failed to send file size metadata");
        return 0;
    }
    
    printf("[METADATA] File size information transmitted: %ld bytes\n", file_size);
    usleep(SIZE_WAIT_TIME_US);
    
    return 1;
}