/* KTP Protocol File Receiver
*
* Receives files over the network using KTP reliability protocol
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "ksocket.h"

// Configuration parameters
#define APP_BUF_SIZE          KTP_MSG_SIZE  // Buffer size for data reception
#define PROGRESS_DISPLAY_FREQ 5             // Show progress every N packets
#define POLL_INTERVAL_US      100000        // Sleep between empty reads (100ms) 
#define MAX_EMPTY_READS       5000          // Maximum consecutive empty reads

// Forward declarations
bool parse_arguments(int argc, char *argv[],
                    char **filename, char **src_ip, int *src_port,
                    char **dst_ip, int *dst_port);
long receive_file_size(int sockfd, struct sockaddr_in *src_addr);
bool receive_file_data(int sockfd, FILE *file, long expected_size);
bool ask_user_to_continue(long received_bytes, long total_bytes);
void display_progress_bar(long current_bytes, long total_bytes);

// IMPLEMENTATION SECTION

int main(int argc, char *argv[]) {
    // Variable declarations
    char *filename = NULL;
    char *src_ip = NULL;
    char *dst_ip = NULL;
    int src_port = 0;
    int dst_port = 0;
    int sockfd = -1;
    FILE *output_file = NULL;
    bool success = false;
    long file_size = 0;
    struct sockaddr_in src_addr;
    
    // Command line processing
    if (parse_arguments(argc, argv, &filename, &src_ip, &src_port, &dst_ip, &dst_port) == false) {
        return EXIT_FAILURE;
    }
    
    // Network initialization
    do {
        // Socket creation
        sockfd = k_socket(AF_INET, SOCK_KTP, 0);
        if (sockfd < 0) {
            fprintf(stderr, "ERROR: Failed to create KTP socket: %s\n", strerror(errno));
            break;
        }
        printf("✓ KTP socket created with descriptor: %d\n", sockfd);
        
        // Address binding
        if (k_bind(sockfd, src_ip, src_port, dst_ip, dst_port) < 0) {
            fprintf(stderr, "ERROR: Failed to bind KTP socket: %s\n", strerror(errno));
            break;
        }
        printf("✓ Socket bound to %s:%d → %s:%d\n", src_ip, src_port, dst_ip, dst_port);
        
        // Allow time for binding to complete
        usleep(500000);  // 500ms
        
        // Metadata exchange
        file_size = receive_file_size(sockfd, &src_addr);
        if (file_size <= 0) {
            fprintf(stderr, "ERROR: Failed to receive valid file size\n");
            break;
        }
        printf("✓ File size metadata received: %ld bytes\n", file_size);
        
        // File creation
        output_file = fopen(filename, "wb");
        if (!output_file) {
            fprintf(stderr, "ERROR: Failed to create output file '%s': %s\n", 
                    filename, strerror(errno));
            break;
        }
        
        // Data reception
        if (receive_file_data(sockfd, output_file, file_size)) {
            printf("✓ File '%s' received successfully\n", filename);
            success = true;
        } else {
            fprintf(stderr, "ERROR: File transfer failed or was incomplete\n");
        }
    } while (0);  // Non-looping do-while for structured error handling
    
    // Cleanup
    printf("Cleaning up resources...\n");
    if (sockfd >= 0) k_close(sockfd);
    if (output_file) fclose(output_file);
    
    // Return status
    return success ? EXIT_SUCCESS : EXIT_FAILURE;
}

// UTILITY FUNCTIONS

bool parse_arguments(int argc, char *argv[], 
                    char **filename, char **src_ip, int *src_port,
                    char **dst_ip, int *dst_port) {
    // Validate argument count
    if (argc != 6) {
        fprintf(stderr, "Usage: %s <src_ip> <src_port> <dst_ip> <dst_port> <output_file>\n", 
                argv[0]);
        return false;
    }

    // Extract arguments
    *src_ip = argv[1];
    *src_port = atoi(argv[2]);
    *dst_ip = argv[3];
    *dst_port = atoi(argv[4]);
    *filename = argv[5];
    
    // Port validation
    bool src_port_valid = (*src_port > 0 && *src_port <= 65535);
    bool dst_port_valid = (*dst_port > 0 && *dst_port <= 65535);
    
    if (!src_port_valid || !dst_port_valid) {
        fprintf(stderr, "ERROR: Port numbers must be between 1 and 65535\n");
        return false;
    }
    
    return true;
}

long receive_file_size(int sockfd, struct sockaddr_in *src_addr) {
    // Local variables
    char size_buffer[64] = {0};
    socklen_t addrlen = sizeof(struct sockaddr_in);
    int attempts = 0;
    const int MAX_ATTEMPTS = 300;  // 30 seconds max wait
    long size = -1;
    
    printf("Waiting for file size metadata...\n");
    
    // Retry loop with timeout
    for (attempts = 0; attempts < MAX_ATTEMPTS; attempts++) {
        ssize_t size_bytes = k_recvfrom(sockfd, size_buffer, sizeof(size_buffer) - 1, 0,
                                      (struct sockaddr *)src_addr, &addrlen);
        
        if (size_bytes > 0) {
            // Ensure null termination
            size_buffer[size_bytes] = '\0';
            
            // Validate data is numeric
            bool valid = true;
            for (int i = 0; size_buffer[i] != '\0'; i++) {
                if (!isdigit(size_buffer[i])) {
                    valid = false;
                    break;
                }
            }
            
            if (!valid) {
                fprintf(stderr, "ERROR: Received invalid file size data\n");
                return -1;
            }
            
            // Convert to number
            size = atol(size_buffer);
            if (size <= 0) {
                fprintf(stderr, "ERROR: Invalid file size value: %ld\n", size);
                return -1;
            }
            
            return size;  // Success case
        } 
        else if (errno != E_KTP_NO_MESSAGE) {
            // Critical error
            fprintf(stderr, "ERROR: Failed to receive file size: %s\n", strerror(errno));
            return -1;
        }
        
        // Delay before next attempt
        usleep(POLL_INTERVAL_US);
    }
    
    fprintf(stderr, "ERROR: Timeout waiting for file size metadata\n");
    return 0;  // Timeout case
}

bool receive_file_data(int sockfd, FILE *file, long expected_size) {
    char buffer[APP_BUF_SIZE];
    struct sockaddr_in src_addr;
    socklen_t addrlen = sizeof(src_addr);
    
    size_t total_received = 0;
    int packet_count = 0;
    int consecutive_empty_reads = 0;
    
    // Start transfer with header display
    printf("┌────────────────────────────────────────────────┐\n");
    printf("│          BEGINNING FILE TRANSFER               │\n");
    printf("└────────────────────────────────────────────────┘\n");

    // Continue loop until all data received
    for (;;) {
        // Check if transfer complete
        if (total_received >= expected_size) {
            break;
        }
        
        // Attempt to receive data
        ssize_t bytes_received = k_recvfrom(sockfd, buffer, APP_BUF_SIZE, 0,
                                          (struct sockaddr *)&src_addr, &addrlen);
        
        // Handle reception outcome
        if (bytes_received < 0) {
            // Case: No message available
            if (errno == E_KTP_NO_MESSAGE) {
                consecutive_empty_reads++;
                
                // Extended timeout handling
                if (consecutive_empty_reads > MAX_EMPTY_READS) {
                    float completion = (float)total_received / expected_size * 100;
                    printf("⚠️  Transfer stalled at %.1f%% (%ld/%ld bytes)\n", 
                           completion, total_received, expected_size);
                    
                    // User interaction for continuation decision
                    if (!ask_user_to_continue(total_received, expected_size)) {
                        return false;
                    }
                    
                    // Reset timeout counter
                    consecutive_empty_reads = 0;
                }
                
                // Brief pause before next attempt
                usleep(POLL_INTERVAL_US);
                continue;
            } 
            
            // Case: Critical error
            fprintf(stderr, "ERROR: Reception failed: %s\n", strerror(errno));
            return false;
        }
        
        // Data received - reset timeout counter
        consecutive_empty_reads = 0;
        
        // Write received data to output file
        size_t written = fwrite(buffer, 1, bytes_received, file);
        if (written != bytes_received) {
            fprintf(stderr, "ERROR: Failed to write to output file\n");
            return false;
        }
        
        // Update transfer statistics
        total_received += bytes_received;
        packet_count++;
        
        // Progress display
        if ((packet_count % PROGRESS_DISPLAY_FREQ) == 0) {
            display_progress_bar(total_received, expected_size);
        }
    }

    // Ensure data is persisted
    fflush(file);
    
    // Display final 100% progress bar
    display_progress_bar(expected_size, expected_size);
    printf("\n Transfer complete! Final status:\n");
    
    // Final statistics display
    printf("\n┌─────────────────────────────────────────────────┐\n");
    printf("│             TRANSFER STATISTICS                 │\n");
    printf("├─────────────────────────────────────────────────┤\n");
    printf("│ Total bytes received: %-25ld │\n", total_received);
    printf("│ Expected file size:   %-25ld │\n", expected_size);
    printf("│ Received packets:     %-25d │\n", packet_count);
    printf("│ Average packet size:  %-25.1f │\n", (float)total_received/packet_count);
    printf("└─────────────────────────────────────────────────┘\n");
    
    return true;
}

void display_progress_bar(long current_bytes, long total_bytes) {
    // Configuration
    const int progress_width = 50;
    
    // Calculate completion percentage
    float completion = (float)current_bytes / total_bytes * 100;
    completion = completion > 100.0 ? 100.0 : completion;
    
    // Determine filled portion
    int filled = (int)((progress_width * current_bytes) / total_bytes);
    filled = current_bytes >= total_bytes ? progress_width : filled;
    
    // Render progress bar
    printf("▕");
    int i = 0;
    while (i < filled) {
        printf("█");
        i++;
    }
    while (i < progress_width) {
        printf("░");
        i++;
    }
    
    printf("▏ %.1f%% (%ld bytes)\n", completion, current_bytes);
}

bool ask_user_to_continue(long received_bytes, long total_bytes) {
    float completion = (float)received_bytes / total_bytes * 100;
    char response = 'y';  // Default to yes
    
    printf("Continue waiting for data? [Y/n]: ");
    fflush(stdout);
    
    if (scanf(" %c", &response) != 1) {
        // Handle read failure - assume yes
        return true;
    }
    
    if (response == 'n' || response == 'N') {
        printf("Transfer aborted at %.1f%% completion.\n", completion);
        return false;
    }
    
    printf("Continuing to wait for more data...\n");
    return true;
}