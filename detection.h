#ifndef DETECTION_H
#define DETECTION_H

#include <vector>
#include <string>

// Define structure for a signature
struct Signature {
    std::string protocol;
    std::string pattern;
};

// function declarations
void load_signatures(const char* filename);
void log_packet(const char* log_message, const char* packet_data);
void detect_port_scanning(const char* src_ip);
void detect_dos_attack(const char* src_ip);
void detect_malware(unsigned char* buffer, int size);
void detect_anomaly(unsigned char* buffer, int size);
void detect_intrusion(unsigned char* buffer, int size);
void compare_with_signatures(unsigned char* buffer, int size, const char* protocol);

#endif // DETECTION_H