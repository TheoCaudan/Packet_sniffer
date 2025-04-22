#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <errno.h>
#include <detection.h>

#define BUFFER_SIZE 65536

void process_packet(unsigned char*, int);
void print_ip_header(unsigned char*, int);
void print_tcp_packet(unsigned char*, int);
void print_udp_packet(unsigned char*, int);
void print_icmp_packet(unsigned char*, int);
void print_data(unsigned char*, int);

int main() {
    int sock_raw;
    struct sockaddr saddr;
    int saddr_len = sizeof(saddr);
    unsigned char buffer[BUFFER_SIZE];

    printf("Starting...\n");

    load_signatures("signatures.txt"); // signatures.txt = MITRE CVE database in txt format (can be changed)

    sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_raw < 0) {
        perror("Socker error");
        return 1;
    }

    while (1) {
        // Receive a packet
        int data_size = recvfrom(sock_raw, buffer, BUFFER_SIZE, 0, &saddr, (socklen_t*)&saddr_len);
        if (data_size < 0) {
            perror("Recvfrom error");
            close(sock_raw);
            return 1;
        }
        // Process the packet
        process_packet(buffer, data_size);
    }
    
    close(sock_raw);
    printf("Finished");
    return 0;
}

void process_packet(unsigned char* buffer, int size) {
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    switch (iph->protocol) {
        case IPPROTO_ICMP:
            print_icmp_packet(buffer, size);
            detect_intrusion(buffer, size);
            break;
        case IPPROTO_TCP:
            print_tcp_packet(buffer, size);
            detect_intrusion(buffer, size);
            break;
        case IPPROTO_UDP:
            print_udp_packet(buffer, size);
            detect_intrusion(buffer,size);
            break;
        default:
            print_ip_header(buffer, size);
            break;
    }
}

void print_ip_header(unsigned char* Buffer, int Size) {
    struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));
    struct sockaddr_in source, dest;
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    printf("\nIP Header\n");

    unsigned int version, ihl, tos, tot_len, id, ttl, protocol, check;
    char src_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN];

    // Assembly optimization for extraction IP header fields
    asm volatile (
        "movb %8, %0\n\t"
        "movb %9, %1\n\t"
        "movb %10, %2\n\t"
        "movw %11, %3\n\t"
        "movw %12, %4\n\t"
        "movb %13, %5\n\t"
        "movb %14, %6\n\t"
        "movw %15, %7\n\t"
        : "=r" (version), "=r" (ihl), "=r" (tos), "=r" (tot_len), "=r" (id), "=r" (ttl), "=r" (protocol), "=r" (check)
        : "m" (iph->version), "m" (iph->ihl), "m" (iph->tos), "m" (iph->tot_len), "m" (iph->id), "m" (iph->ttl), "m" (iph->protocol), "m" (iph->check)
    );

    inet_ntop(AF_INET, &source.sin_addr, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &dest.sin_addr, dest_ip, INET_ADDRSTRLEN);

    printf("    |-IP Version       : %d\n", version);
    printf("    |-IP Header Length : %d DWORDS or %d Bytes\n", ihl, ihl * 4);
    printf("    |-Type Of Service  : %d\n", tos);
    printf("    |-IP Total Length  : %d Bytes(Size of Packet)\n", ntohs(tot_len));
    printf("    |-Identification   : %d\n", ntohs(id));
    printf("    |-TTL              : %d\n", ttl);
    printf("    |-Protocol         : %d\n", protocol);
    printf("    |-Checksum         : %d\n", ntohs(check));
    printf("    |-Source IP        : %s\n", src_ip);
    printf("    |-Destination IP   : %s\n", dest_ip);
}

void print_tcp_packet(unsigned char* Buffer, int Size) {
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)(Buffer + iphdrlen + sizeof(struct ethhdr));

    printf("\n\n*****************************TCP Packet*****************************\n");

    print_ip_header(Buffer, Size);

    printf("\nTCP Header\n");

    unsigned int source_port, dest_port, seq, ack_seq, doff, urg, ack, psh, rst, syn, fin, window, check, urg_ptr;

    // Assembly opti for extracting TCP header fields
    asm volatile (
        "movw %16, %0\n\t"
        "movw %17, %1\n\t"
        "movl %18, %2\n\t"
        "movl %19, %3\n\t"
        "movb %20, %4\n\t"
        "movb %21, %5\n\t"
        "movb %22, %6\n\t"
        "movb %23, %7\n\t"
        "movb %24, %8\n\t"
        "movb %25, %9\n\t"
        "movw %26, %10\n\t"
        "movw %27, %11\n\t"
        "movw %28, %12\n\t"
        : "=r" (source_port), "=r" (dest_port), "=r" (seq), "=r" (ack_seq), "=r" (doff), "=r" (urg), "=r" (ack), "=r" (psh), "=r" (rst), "=r" (syn), "=r" (fin), "=r" (window), "=r" (check), "=r" (urg_ptr)
        : "m" (tcph->source), "m" (tcph->dest), "m" (tcph->seq), "m" (tcph->ack_seq), "m" (tcph->doff), "m" (tcph->urg), "m" (tcph->ack), "m" (tcph->psh), "m" (tcph->rst), "m" (tcph->syn), "m" (tcph->fin), "m" (tcph->window), "m" (tcph->check), "m" (tcph->urg_ptr)
    );

    printf("    |-Source Port          : %u\n", ntohs(source_port));
    printf("    |-Destination Port     : %u\n", ntohs(dest_port));
    printf("    |-Sequence Number      : %u\n", ntohl(seq));
    printf("    |-Acknowledge Number   : %u\n", ntohl(ack_seq));
    printf("    |-Header Length        : %d DWORDS or %d BYTES\n", doff, doff * 4);
    printf("    |-Urgent Flag          : %d\n", urg);
    printf("    |-Acknowledgement Flag : %d\n", ack);
    printf("    |-Push Flag            : %d\n", psh);
    printf("    |-Reset Flag           : %d\n", rst);
    printf("    |-Synchronise Flag     : %d\n", syn);
    printf("    |-Finish Flag          : %d\n", fin);
    printf("    |-Window               : %d\n", ntohs(window));
    printf("    |-Checksum             : %d\n", ntohs(check));
    printf("    |-Urgent Pointer       : %d\n", urg_ptr);
    printf("\n");
    printf("                DATA Dump               ");
    printf("\n");

    print_data(Buffer + iphdrlen + doff * 4, (Size - doff * 4 - iphdrlen));

    printf("\n###########################################");
}

void print_udp_packet(unsigned char *Buffer, int Size) {
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));
    iphdrlen = iph-ihl * 4;

    struct udphdr *udph = (struct udphdr *)(Buffer + iphdrlen + sizeof(struct ethhdr));

    printf("\n\n*****************************UDP Packet*****************************\n");

    print_ip_header(Buffer, Size);

    printf("\nUDP Header\n");

    unsigned int source_port, dest_port, len, check;

    // Assembly opti for extract UDP header fields
    asm volatile (
        "movw %8, %0\n\t"
        "movw %9, %1\n\t"
        "movw %10, %2\n\t"
        "movw %11, %3\n\t"
        : "=r" (source_port), "=r" (dest_port), "=r" (len), "=r" (check)
        : "m" (udph->source), "m" (udph->dest), "m" (udph->len, "m" (udph->check))
    );

    printf("    |-Source Port      : %d\n", ntohs(source_port));
    printf("    |-Destination Port : %d\n", ntohs(dest_port));
    printf("    |-UDP Length       : %d\n", ntohs(len));
    printf("    |-UDP Checksum     : %d\n", ntohs(check));

    printf("\n");
    printf("IP Header\n");
    print_data(Buffer, iphdrlen);

    printf("UDP Header\n");
    print_data(Buffer + iphdrlen, sizeof(udph));

    printf("Data Payload\n");
    print_data(Buffer + iphdrlen + sizeof(udph), (Size - sizeof(udph) - iphdrlen));

    printf("\n###########################################");
}

void print_icmp_packet(unsigned char* Buffer, int Size) {
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;

    struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen + sizeof(struct ethhdr));

    printf("\n\n*****************************ICMP Packet*****************************\n");

    print_ip_header(Buffer, Size);

    printf("\nICMP Header\n");

    unsigned int type, code, checksum;

    // Assembly opti for extract ICMP header fileds
    asm volatile (
        "movb %4, %0\n\t"
        "movb %5, %1\n\t"
        "movw %6, %2\n\t"
        : "=r" (type), "=r" (code), "=r" (checksum)
        : "m" (icmph->type), "m" (icmph->code), "m" (icmph->checksum)
    );

    printf("    |-Type         : %d", type);

    if (type == 11) {
        printf("    (TTL Expired)\n");
    } else if (type == ICMP_ECHOREPLY) {
        printf("    (ICMP Echo Reply)\n");
    }

    printf("    |-Code         : %d\n", code);
    printf("    |-Checksum     : %d\n", ntohs(checksum));
    printf("\n");

    printf("IP Header\n");
    print_data(Buffer, iphdrlen);

    printf("ICMP Header\n");
    print_data(Buffer + iphdrlen, sizeof(icmph));

    printf("Data Payload\n");
    print_data(Buffer + iphdrlen + sizeof(icmph), (Size - sizeof(icmph) - iphdrlen));

    printf("\n###########################################");
}

void print_data(unsigned char* data, int Size) {
    int i, j;
    for (i = 0; i < Size; i++) {
        if ((i != 0) && (i % 16 == 0)) {
            if ((data[j] >= 32) && (data[j] <= 128)) { //checks if it is a number or alphabet character
                printf("%c", (unsigned char)data[j]);
            } else {
                printf("."); // if it is not an alphanumeric character -> print a dot
            }
        }
        printf("\n");

        if (i % 16 == 0) printf("       ");
            printf(" %02X", (unsigned int)data[i]);

        if (i == (Size - 1)) {
            for (j = 0; j < 15 - (i % 16); j++) {
                if ((data[j] >= 32) && (data[j] <= 128)) {
                    printf("%c", (unsigned char)data[j]);
                } else {
                    printf(".");
                }
            }
            printf("\n");
        }
    }
}