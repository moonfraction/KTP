/*******************************************************************************
 * KTP Protocol File Receiver Application
 *
 * Receives a file sent using the KTP protocol and saves it to disk
 ******************************************************************************/

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
 
 /* Application configuration */
 #define APP_BUF_SIZE          KTP_MSG_SIZE  /* Buffer size for data reception */
 #define PROGRESS_DISPLAY_FREQ 5             /* Show progress every N packets */
 #define POLL_INTERVAL_US      100000        /* Sleep between empty reads (100ms) */
 #define MAX_EMPTY_READS       5000          /* Maximum consecutive empty reads */
 
 /* Function prototypes */
bool parse_arguments(int argc, char *argv[], 
    char **filename, char **src_ip, int *src_port,
    char **dst_ip, int *dst_port);
long receive_file_size(int sockfd, struct sockaddr_in *src_addr);
bool receive_file_data(int sockfd, FILE *file, long expected_size);
bool ask_user_to_continue(long received_bytes, long total_bytes);
void display_progress_bar(long current_bytes, long total_bytes);
 
 /******************************************************************************/
 /*                             MAIN FUNCTION                                  */
 /******************************************************************************/

int main(int argc, char *argv[]) {
    char *filename, *src_ip, *dst_ip;
    int src_port, dst_port;
    int sockfd = -1;
    FILE *output_file = NULL;
    bool success = false;
    
    /*-------------------------------------------------------------------------
    * Setup phase
    *-------------------------------------------------------------------------*/
    
    /* Parse command line arguments */
    if (!parse_arguments(argc, argv, &filename, &src_ip, &src_port, &dst_ip, &dst_port)) {
        return EXIT_FAILURE;
    }
    
    /* Create KTP socket */
    sockfd = k_socket(AF_INET, SOCK_KTP, 0);
    if (sockfd < 0) {
        fprintf(stderr, "ERROR: Failed to create KTP socket: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }
    printf("✓ KTP socket created with descriptor: %d\n", sockfd);
    
    /* Bind socket to network addresses */
    if (k_bind(sockfd, src_ip, src_port, dst_ip, dst_port) < 0) {
        fprintf(stderr, "ERROR: Failed to bind KTP socket: %s\n", strerror(errno));
        goto cleanup;
    }
    printf("✓ Socket bound to %s:%d → %s:%d\n", src_ip, src_port, dst_ip, dst_port);
    
    /* Short delay to ensure binding is complete */
    usleep(500000);  /* 500ms */
    
    /*-------------------------------------------------------------------------
    * Transfer phase
    *-------------------------------------------------------------------------*/
    
    /* Source address structure for receive operations */
    struct sockaddr_in src_addr;
    
    /* Receive expected file size */
    long file_size = receive_file_size(sockfd, &src_addr);
    if (file_size <= 0) {
        fprintf(stderr, "ERROR: Failed to receive valid file size\n");
        goto cleanup;
    }
    printf("✓ File size metadata received: %ld bytes\n", file_size);
    
    /* Create output file */
    output_file = fopen(filename, "wb");
    if (!output_file) {
        fprintf(stderr, "ERROR: Failed to create output file '%s': %s\n", 
                filename, strerror(errno));
        goto cleanup;
    }
    
    /* Receive and save file data */
    if (!receive_file_data(sockfd, output_file, file_size)) {
        fprintf(stderr, "ERROR: File transfer failed or was incomplete\n");
        goto cleanup;
    }
    
    /* Success */
    printf("✓ File '%s' received successfully\n", filename);
    success = true;

cleanup:
    /* Release resources */
    printf("Cleaning up resources...\n");
    if (sockfd >= 0) {
        k_close(sockfd);
    }
    if (output_file) {
        fclose(output_file);
    }
    
    return success ? EXIT_SUCCESS : EXIT_FAILURE;
}

/******************************************************************************/
/*                            HELPER FUNCTIONS                                */
/******************************************************************************/

/**
 * Parse command line arguments
 *
 * @param argc      Argument count
 * @param argv      Argument values
 * @param filename  Output parameter for filename
 * @param src_ip    Output parameter for source IP
 * @param src_port  Output parameter for source port
 * @param dst_ip    Output parameter for destination IP
 * @param dst_port  Output parameter for destination port
 * @return true if arguments are valid, false otherwise
 */
bool parse_arguments(int argc, char *argv[], 
                    char **filename, char **src_ip, int *src_port,
                    char **dst_ip, int *dst_port) {
    if (argc != 6) {
        fprintf(stderr, "Usage: %s <src_ip> <src_port> <dst_ip> <dst_port> <output_file>\n", argv[0]);
        return false;
    }

    *src_ip = argv[1];
    *src_port = atoi(argv[2]);
    *dst_ip = argv[3];
    *dst_port = atoi(argv[4]);
    *filename = argv[5];
    
    /* Validate ports */
    if (*src_port <= 0 || *src_port > 65535 || *dst_port <= 0 || *dst_port > 65535) {
        fprintf(stderr, "ERROR: Port numbers must be between 1 and 65535\n");
        return false;
    }
    
    return true;
}

 
/**
 * Receive file size metadata from sender
 *
 * @param sockfd    KTP socket descriptor
 * @param src_addr  Source address structure
 * @return File size in bytes, or ≤0 on failure
 */
long receive_file_size(int sockfd, struct sockaddr_in *src_addr) {
    char size_buffer[64] = {0};
    socklen_t addrlen = sizeof(struct sockaddr_in);
    int attempts = 0;
    const int MAX_ATTEMPTS = 300;  /* 30 seconds max wait */
    
    printf("Waiting for file size metadata...\n");
    
    /* Keep trying until we receive the file size or timeout */
    while (attempts++ < MAX_ATTEMPTS) {
        ssize_t size_bytes = k_recvfrom(sockfd, size_buffer, sizeof(size_buffer) - 1, 0,
                                      (struct sockaddr *)src_addr, &addrlen);
        
        if (size_bytes > 0) {
            /* Ensure null termination */
            size_buffer[size_bytes] = '\0';
            
            /* Validate that we received a valid number */
            for (int i = 0; i < size_bytes; i++) {
                if (size_buffer[i] != '\0' && !isdigit(size_buffer[i])) {
                    fprintf(stderr, "ERROR: Received invalid file size data\n");
                    return -1;
                }
            }
            
            long size = atol(size_buffer);
            if (size <= 0) {
                fprintf(stderr, "ERROR: Invalid file size value: %ld\n", size);
                return -1;
            }
            
            return size;
        } 
        else if (errno != E_KTP_NO_MESSAGE) {
            /* Error other than "no message available" */
            fprintf(stderr, "ERROR: Failed to receive file size: %s\n", strerror(errno));
            return -1;
        }
        
        /* Wait before retrying */
        usleep(POLL_INTERVAL_US);
    }
    
    fprintf(stderr, "ERROR: Timeout waiting for file size metadata\n");
    return 0;
}
 /**
 * Receive file data and write to output file
 *
 * @param sockfd         KTP socket descriptor
 * @param file           Open file handle for writing
 * @param expected_size  Expected file size in bytes
 * @return true if transfer completed successfully, false otherwise
 */
bool receive_file_data(int sockfd, FILE *file, long expected_size) {
    char buffer[APP_BUF_SIZE];
    struct sockaddr_in src_addr;
    socklen_t addrlen = sizeof(src_addr);
    
    size_t total_received = 0;
    int packet_count = 0;
    int consecutive_empty_reads = 0;
    
    printf("┌────────────────────────────────────────────────┐\n");
    printf("│          BEGINNING FILE TRANSFER               │\n");
    printf("└────────────────────────────────────────────────┘\n");

    /* Main reception loop */
    while (total_received < expected_size) {
        ssize_t bytes_received = k_recvfrom(sockfd, buffer, APP_BUF_SIZE, 0,
                                          (struct sockaddr *)&src_addr, &addrlen);
        
        if (bytes_received < 0) {
            /* Handle reception errors */
            if (errno == E_KTP_NO_MESSAGE) {
                consecutive_empty_reads++;
                
                /* Check for timeout condition */
                if (consecutive_empty_reads > MAX_EMPTY_READS) {
                    float completion = (float)total_received / expected_size * 100;
                    printf("⚠️  Transfer stalled at %.1f%% (%ld/%ld bytes)\n", 
                           completion, total_received, expected_size);
                    
                    if (!ask_user_to_continue(total_received, expected_size)) {
                        return false;
                    }
                    
                    /* Reset counter and continue waiting */
                    consecutive_empty_reads = 0;
                }
                
                /* Brief pause before next attempt */
                usleep(POLL_INTERVAL_US);
                continue;
            } 
            else {
                /* Fatal error */
                fprintf(stderr, "ERROR: Reception failed: %s\n", strerror(errno));
                return false;
            }
        }
        
        /* Successfully received data */
        consecutive_empty_reads = 0;
        
        /* Write data to file */
        if (fwrite(buffer, 1, bytes_received, file) != bytes_received) {
            fprintf(stderr, "ERROR: Failed to write to output file\n");
            return false;
        }
        
        /* Update statistics */
        total_received += bytes_received;
        packet_count++;
        
        /* Display progress periodically */
        if (packet_count % PROGRESS_DISPLAY_FREQ == 0 || total_received >= expected_size) {
            display_progress_bar(total_received, expected_size);
        }
    }

    /* Always display final 100% progress bar */
    // display_progress_bar(expected_size, expected_size);

    /* Final statistics */
    printf("\n┌─────────────────────────────────────────────────┐\n");
    printf("│             TRANSFER STATISTICS                 │\n");
    printf("├─────────────────────────────────────────────────┤\n");
    printf("│ Total bytes received: %-25ld │\n", total_received);
    printf("│ Expected file size:   %-25ld │\n", expected_size);
    printf("│ Received packets:     %-25d │\n", packet_count);
    printf("│ Average packet size:  %-25.1f │\n", (float)total_received/packet_count);
    printf("└─────────────────────────────────────────────────┘\n");
    
    /* Ensure all data is flushed to disk */
    fflush(file);
    
    return total_received >= expected_size;
}

/**
 * Display a progress bar showing file transfer status
 *
 * @param current_bytes  Bytes received so far
 * @param total_bytes    Total expected bytes
 */
void display_progress_bar(long current_bytes, long total_bytes) {
    const int progress_width = 50;
    float completion = (float)current_bytes / total_bytes * 100;
    
    /* Ensure we don't exceed 100% due to floating point errors */
    if (completion > 100.0) completion = 100.0;
    
    int filled = (int)(progress_width * completion / 100);
    
    /* Ensure the bar is completely filled at 100% */
    if (current_bytes >= total_bytes) filled = progress_width;
    
    printf("▕");
    for (int i = 0; i < progress_width; i++) {
        printf(i < filled ? "█" : "░");
    }
    
    printf("▏ %.1f%% (%ld bytes)\n", completion, current_bytes);
}
 /**
  * Ask user whether to continue waiting for data
  *
  * @param received_bytes  Bytes received so far
  * @param total_bytes     Expected total bytes
  * @return true if user wants to continue, false otherwise
  */
 bool ask_user_to_continue(long received_bytes, long total_bytes) {
     float completion = (float)received_bytes / total_bytes * 100;
     
     printf("Continue waiting for data? [Y/n]: ");
     fflush(stdout);
     
     char response = 'y';  /* Default to yes */
     scanf(" %c", &response);
     
     if (response == 'n' || response == 'N') {
         printf("Transfer aborted at %.1f%% completion.\n", completion);
         return false;
     }
     
     printf("Continuing to wait for more data...\n");
     return true;
 }