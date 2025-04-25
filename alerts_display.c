#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define CYAN    "\033[1;36m"
#define RESET   "\033[0m"

#define MAX_LINES 30

void live_display(const char* filepath) {
    const char *log_path = filepath;
    char *lines[MAX_LINES];
    int count = 0;

    for (int i = 0; i < MAX_LINES; ++i)
        lines[i] = NULL;

    while (1) {
        system("clear");
        printf(YELLOW "========[ LIVE ALERT LOG (Last %d) ]========\n" RESET, MAX_LINES);
        printf(CYAN "   TYPE         SOURCE IP       TIME\n" RESET);
        printf("----------------------------------------------------\n");

        FILE *log = fopen(log_path, "r");
        if (!log) {
            perror("Failed to open alert log");
            sleep(2);
            continue;
        }

        char buffer[512];
        count = 0;

        while (fgets(buffer, sizeof(buffer), log)) {
            if (lines[count % MAX_LINES])
                free(lines[count % MAX_LINES]);
            lines[count % MAX_LINES] = strdup(buffer);
            count++;
        }
        fclose(log);

        int start = (count > MAX_LINES) ? count - MAX_LINES : 0;
        for (int i = start; i < count; ++i) {
            char *line = lines[i % MAX_LINES];
            if (!line) continue;

            char *type = strstr(line, "ALERT:");
            char ip[64] = "", time[64] = "";

            strncpy(time, line + 1, 24); time[24] = '\0';

            if (type) {
                type += 7;
                char *ip_start = strstr(type, "from ");
                if (ip_start) {
                    ip_start += 5;
                    sscanf(ip_start, "%s", ip);
                    type[ip_start - type - 5] = '\0';
                }
                printf(GREEN " %-13s %-16s %-20s\n" RESET, type, ip, time);
            }
        }

        sleep(2);
    }

    return;
}


int main() {
    const char *log_path = "/home/kali/NIDS/alerts.log";  // adjust path as needed
    live_display(log_path);
    return 0;
}
