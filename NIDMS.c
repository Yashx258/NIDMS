#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <semaphore.h>
#include <time.h>

#define BUFFER_SIZE 50
#define MAX_TRACKED_IPS 100
#define THRESHOLD 100
#define TIME_WINDOW 5

#define MAX_PORT_SCAN_IPS 100
#define MAX_PORTS_TRACKED 100
#define PORT_SCAN_THRESHOLD 5
#define SCAN_TIME_WINDOW 5

#define MAX_BRUTE_FORCE_IPS 100
#define BRUTE_FORCE_THRESHOLD 10
#define BRUTE_TIME_WINDOW 5

typedef struct {
    char ip[16];
    int attempt_count;
    time_t first_seen;
} BruteForceTrack;

BruteForceTrack brute_ips[MAX_BRUTE_FORCE_IPS];
int brute_count = 0;


typedef struct {
    unsigned char packet[65536];
    int size;
} Packet;

typedef struct {
    char ip[16];
    int syn_count;
    time_t first_seen;
} IPTrack;

typedef struct {
    char ip[16];
    int ports[MAX_PORTS_TRACKED];
    int port_count;
    time_t first_seen;
} PortScanTrack;

PortScanTrack port_scans[MAX_PORT_SCAN_IPS];
int scan_count = 0;

// Global circular buffer and pointers
Packet circular_buffer[BUFFER_SIZE];
int front = 0, rear = 0;

// Global IP tracker
IPTrack tracked_ips[MAX_TRACKED_IPS];
int tracked_count = 0;

// Sync primitives
pthread_mutex_t buffer_mutex;
sem_t empty_slots, filled_slots;

// Pipe for IPC
int pipefd[2];

pthread_mutex_t mutex;
sem_t write_lock;
int reader_count = 0;

int port_already_tracked(int *ports, int count, int port) {
    for (int i = 0; i < count; ++i) {
        if (ports[i] == port) return 1;
    }
    return 0;
}

// Utility: Check if SYN packet
int is_syn_packet(struct iphdr *ip, unsigned char *buffer) {
    if (ip->protocol != 6) return 0;
    struct tcphdr *tcp = (struct tcphdr*)(buffer + sizeof(struct ethhdr) + ip->ihl * 4);
    return (tcp->syn && !tcp->ack);
}

// Utility: Check for SYN flood and log if needed
void check_and_track_syn(char *src_ip) {
    time_t now = time(NULL);
    for (int i = 0; i < tracked_count; ++i) {
        if (strcmp(tracked_ips[i].ip, src_ip) == 0) {
            if (difftime(now, tracked_ips[i].first_seen) > TIME_WINDOW) {
                tracked_ips[i].first_seen = now;
                tracked_ips[i].syn_count = 1;
            } else {
                tracked_ips[i].syn_count++;
                if (tracked_ips[i].syn_count > THRESHOLD) {
                    char *timestamp = ctime(&now);
                    timestamp[strcspn(timestamp, "\n")] = '\0';
                    
                    char alert_msg[256];
                    snprintf(alert_msg, sizeof(alert_msg),
                             "[%s] ALERT: SYN flood from %s (%d SYNs in %d seconds)\n",
                             timestamp, src_ip, tracked_ips[i].syn_count, TIME_WINDOW);

                    printf("%s", alert_msg);
                    write(pipefd[1], alert_msg, strlen(alert_msg));
                }
            }
            return;
        }
    }
    if (tracked_count < MAX_TRACKED_IPS) {
        strcpy(tracked_ips[tracked_count].ip, src_ip);
        tracked_ips[tracked_count].syn_count = 1;
        tracked_ips[tracked_count].first_seen = now;
        tracked_count++;
    }
}

void check_port_scan(char *src_ip, int dst_port) {
    time_t now = time(NULL);

    for (int i = 0; i < scan_count; ++i) {
        if (strcmp(port_scans[i].ip, src_ip) == 0) {
            if (difftime(now, port_scans[i].first_seen) > SCAN_TIME_WINDOW) {
                port_scans[i].first_seen = now;
                port_scans[i].port_count = 0;
            }

            if (!port_already_tracked(port_scans[i].ports, port_scans[i].port_count, dst_port)) {
                if (port_scans[i].port_count < MAX_PORTS_TRACKED) {
                    port_scans[i].ports[port_scans[i].port_count++] = dst_port;
                    
             	    printf("[DEBUG] %s hit port %d (total: %d)\n", src_ip, dst_port, port_scans[i].port_count);
                }
            }

            if (port_scans[i].port_count >= PORT_SCAN_THRESHOLD) {
                char *timestamp = ctime(&now);
                timestamp[strcspn(timestamp, "\n")] = '\0';
                char alert_msg[256];
                snprintf(alert_msg, sizeof(alert_msg),
                         "[%s] ALERT: Port scan detected from %s (%d unique ports in %d seconds)\n",
                         timestamp, src_ip, port_scans[i].port_count, SCAN_TIME_WINDOW);
                printf("%s", alert_msg);
                write(pipefd[1], alert_msg, strlen(alert_msg));
                port_scans[i].port_count = 0; // Reset after alert
            }

            return;
        }
    }

    if (scan_count < MAX_PORT_SCAN_IPS) {
        strcpy(port_scans[scan_count].ip, src_ip);
        port_scans[scan_count].ports[0] = dst_port;
        port_scans[scan_count].port_count = 1;
        port_scans[scan_count].first_seen = now;
        scan_count++;
    }
}

int is_login_port(int port) {
    return port == 22 || port == 21 || port == 23 || port == 80 || port == 443;
}

void check_brute_force(char *src_ip, int dst_port) {
    if (!is_login_port(dst_port)) return;

    time_t now = time(NULL);

    for (int i = 0; i < brute_count; ++i) {
        if (strcmp(brute_ips[i].ip, src_ip) == 0) {
            if (difftime(now, brute_ips[i].first_seen) > BRUTE_TIME_WINDOW) {
                brute_ips[i].first_seen = now;
                brute_ips[i].attempt_count = 1;
            } else {
                brute_ips[i].attempt_count++;
                if (brute_ips[i].attempt_count >= BRUTE_FORCE_THRESHOLD) {
                    char *timestamp = ctime(&now);
                    timestamp[strcspn(timestamp, "\n")] = '\0';
                    char alert_msg[256];
                    snprintf(alert_msg, sizeof(alert_msg),
                             "[%s] ALERT: Brute-force attempt detected from %s (%d login attempts in %d seconds)\n",
                             timestamp, src_ip, brute_ips[i].attempt_count, BRUTE_TIME_WINDOW);
                    printf("%s", alert_msg);
                    write(pipefd[1], alert_msg, strlen(alert_msg));
                    brute_ips[i].attempt_count = 0;
                }
            }
            return;
        }
    }

    if (brute_count < MAX_BRUTE_FORCE_IPS) {
        strcpy(brute_ips[brute_count].ip, src_ip);
        brute_ips[brute_count].attempt_count = 1;
        brute_ips[brute_count].first_seen = now;
        brute_count++;
    }
}


// Producer thread: captures packets
void* packet_producer(void* arg) {
    int sock = *(int*)arg;
    unsigned char buffer[65536];
    while (1) {
        int size = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
        if (size < 0) continue;

        sem_wait(&empty_slots);
        pthread_mutex_lock(&buffer_mutex);

        memcpy(circular_buffer[rear].packet, buffer, size);
        circular_buffer[rear].size = size;
        rear = (rear + 1) % BUFFER_SIZE;

        pthread_mutex_unlock(&buffer_mutex);
        sem_post(&filled_slots);
    }
    return NULL;
}

// Consumer thread: analyzes packets
void* packet_consumer(void* arg) {
    while (1) {
        sem_wait(&filled_slots);
        pthread_mutex_lock(&buffer_mutex);

        Packet pkt = circular_buffer[front];
        front = (front + 1) % BUFFER_SIZE;

        pthread_mutex_unlock(&buffer_mutex);
        sem_post(&empty_slots);

        struct ethhdr *eth = (struct ethhdr *)pkt.packet;
        if (ntohs(eth->h_proto) == 0x0800) {
            struct iphdr *ip = (struct iphdr*)(pkt.packet + sizeof(struct ethhdr));
            struct sockaddr_in src;
            src.sin_addr.s_addr = ip->saddr;
            char *src_ip = inet_ntoa(src.sin_addr);

            if (is_syn_packet(ip, pkt.packet)) {
                printf("SYN packet from: %s\n", src_ip);
                check_and_track_syn(src_ip);
                
                struct tcphdr *tcp = (struct tcphdr*)(pkt.packet + sizeof(struct ethhdr) + ip->ihl * 4);
		int dst_port = ntohs(tcp->dest);  // Destination port

		check_port_scan(src_ip, dst_port);
		check_brute_force(src_ip, dst_port);
            }
        }
    }
    return NULL;
}

//Reader entry
void start_read() {
    pthread_mutex_lock(&mutex);
    reader_count++;
    if (reader_count == 1)
        sem_wait(&write_lock); // first reader locks writer
    pthread_mutex_unlock(&mutex);
}

// Reader exits
void end_read() {
    pthread_mutex_lock(&mutex);
    reader_count--;
    if (reader_count == 0)
        sem_post(&write_lock); // last reader unlocks writer
    pthread_mutex_unlock(&mutex);
}

// Writer logic
void start_write() {
    sem_wait(&write_lock); // Writer blocks all readers
}

void end_write() {
    sem_post(&write_lock);
}

void run_logger_process() {
    char buffer[512];
    while (1) {
        ssize_t len = read(pipefd[0], buffer, sizeof(buffer) - 1);
        if (len > 0) {
            buffer[len] = '\0';
            printf("[LOGGER] Received alert: %s\n", buffer);
            start_write();
            FILE *log = fopen("/home/kali/NIDS/alerts.log", "a");
	if (log) {
	    fprintf(log, "%s", buffer);
	    fflush(log);                 // Flush stdio buffer
    fsync(fileno(log)); 
	    fclose(log);
	    printf("[LOGGER] Logged to file successfully.\n");
	} else {
	    perror("Failed to open alerts.log");
	}
            end_write();
        }
    }
}

void* log_reader(void* arg) {
    while (1) {
        start_read();
        FILE *log = fopen("/home/kali/NIDS/alerts.log", "r");
        if (log) {
            char line[256];
            printf("\n--- Log Snapshot ---\n");
            while (fgets(line, sizeof(line), log)) {
                printf("%s", line);
            }
            fclose(log);
        }
        end_read();
        sleep(2); // simulate periodic monitoring
    }
}

// Main function
int main() {
    if (pipe(pipefd) == -1) {
        perror("Pipe creation failed");
        return 1;
    }

    pid_t pid = fork();

    if (pid < 0) {
        perror("Fork failed");
        return 1;
    }

    if (pid == 0) {
        printf("[CHILD] Logger started.\n");  // <== MUST SEE THIS
        close(pipefd[1]);
        run_logger_process();
        exit(0);
    }

    // Parent process: packet sniffer
    close(pipefd[0]); // Close read-end

    int raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_socket < 0) {
        perror("Socket creation failed");
        return 1;
    }

    char *interface = "lo";
    if (setsockopt(raw_socket, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface)) < 0) {
        perror("Bind to interface failed");
        close(raw_socket);
        return 1;
    }

    // Init mutex and semaphores
    pthread_mutex_init(&buffer_mutex, NULL);
    sem_init(&empty_slots, 0, BUFFER_SIZE);
    sem_init(&filled_slots, 0, 0);
    
    pthread_t log_display;
    pthread_create(&log_display, NULL, log_reader, NULL);

    pthread_t producer_thread, consumer_thread;
    pthread_create(&producer_thread, NULL, packet_producer, &raw_socket);
    pthread_create(&consumer_thread, NULL, packet_consumer, NULL);

    pthread_join(producer_thread, NULL);
    pthread_join(consumer_thread, NULL);

    pthread_join(log_display, NULL);

    close(raw_socket);
    return 0;
}
