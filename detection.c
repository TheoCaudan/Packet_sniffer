#include "detection.h"
#include <map>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <ctime>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <arpa/inet.h>
#include <iostream>

std::vector<Signature> signatures;
std::map<std::string, int> port_scan_count;
std::map<std::string, time_t> port_scan_time;
std::map<std::string, int> dos_count;
std::map<std::string, time_t> dos_time;
std::vector<int> packet_sizes;

void load_signatures(const char* filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        perror("Error opening signatures file");
        return;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue; // skip comments and empty lines

        std::istringstream iss(line);
        Signature sig;
        iss >> sig.protocol >> sig.pattern;
        signatures.push_back(sig);
    }

    file.close();
}

void log_packet(const char* log_message, const char* packet_data) {
    FILE *logfile = fopen(LOG_FILE, "a");
    if (logfile == NULL) {
        perror("Error opening log file");
        return;
    }

    time_t now;
    time(&now);
    fprintf(logfile, "Time; %s", ctime(&now));
    fprintf(logfile, "Message: %s\n", log_message);
    fprintf(logfile, "Packet Data: %s\n\n", packet_data);
    fclose(logfile);
}

void detect_port_scanning(const char* src_ip) {
    time_t now = time(NULL);
    if (port_scan_count.find(src_ip) == port_scan_count.end()) {
        port_scan_count[src_ip] = 1;
        port_scan_time[src_ip] = now;
    } else {
        port_scan_count[src_ip]++;
        if (difftime(now, port_scan_time[src_ip]) < 60) { // threshold of 60secs
            if (port_scan_count[src_ip] > 10) { // threshold of 10 scans from the same IP address
                char log_message[256];
                snprintf(log_message, sizeof(log_message), "Potential port scanning detected from %s", src_ip);
                log_packet(log_message, src_ip);
                printf("%s\n", log_message);
                port_scan_count[src_ip] = 0; // reset count after detection
            }
        } else {
            port_scan_count[src_ip] = 1; // reset count if time threshold exceeded
            port_scan_time[src_ip] = now;
        }
    }
}

void detect_dos_attack(const char* src_ip) {
    time_t now = time(NULL);
    if (dos_count.find(src_ip) == dos_count.end()) {
        dos_count[src_ip] = 1;
        dos_time[src_ip] = now;
    } else {
        dos_count[src_ip]++;
        if (difftime(now, dos_time[src_ip]) < 60) {
            if (dos_count[src_ip] > 1000000) {
                char log_message[256];
                snprintf(log_message, sizeof(log_message), "Potential DoS attack detected from %s", src_ip);
                log_packet(log_message, src_ip);
                printf("%s\n", log_message);
                dos_count[src_ip] = 0; // reset count after detection
            }
        } else {
            dos_count[src_ip] = 1; // reset count if time threshold exceeded
            dos_time[src_ip] = now;
        }
    }
}

void detect_malware(unsigned char * buffer, int size) {
    for (const auto& sig : signatures) {
        if (memmem(buffer, size, sig.pattern.c_str(), sig.pattern.size()) != NULL) {
            char log_message[256];
            snprintf(log_message, sizeof(log_message), "Potential malware detected: %s", sig.pattern.c_str());
            log_packet(log_message, (char*)buffer);
            printf("%s\n", log_message);
        }
    }
}

void detect_anomaly(unsigned char* buffer, int size) {
    packet_sizes.push_back(size);
    if (packet_sizes.size() > 100) {
        packet_sizes.erase(packet_sizes.begin());
    }

    double average_size = std::accumulate(packet_sizes.begin(), packet_sizes.end(), 0.0) / packet_sizes.size();
    if (size > average_size * 2) {
        char log_message[256];
        snprintf(log_message, sizeof(log_message), "Anomaly detected: packet size %d exceeds average %f", size, average_size);
        log_packet(log_message, (char*)buffer);
        printf("%s\n", log_message);
    }
}
