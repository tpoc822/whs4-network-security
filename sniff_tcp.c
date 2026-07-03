
#include <netinet/in.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "myheader.h"

#define DEFAULT_IFACE "enp0s3"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    /* IPv4 패킷만 처리 (0x0800) */
    if (ntohs(eth->ether_type) != 0x0800) {
        return;
    }

    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    int ip_header_len = ip->iph_ihl * 4;   /* IHL 필드는 4바이트 단위 */

    /* TCP 프로토콜만 처리 (UDP는 무시) */
    if (ip->iph_protocol != IPPROTO_TCP) {
        return;
    }

    struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);
    int tcp_header_len = TH_OFF(tcp) * 4;  /* Data Offset 필드도 4바이트 단위 */

    printf("=========================================================\n");

    /* Ethernet Header: src mac / dst mac */
    printf("[Ethernet Header]\n");
    printf("  Src MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("  Dst MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    /* IP Header: src ip / dst ip */
    printf("[IP Header]\n");
    printf("  Src IP  : %s\n", inet_ntoa(ip->iph_sourceip));
    printf("  Dst IP  : %s\n", inet_ntoa(ip->iph_destip));
    printf("  IP Header Len : %d bytes\n", ip_header_len);

    /* TCP Header: src port / dst port */
    printf("[TCP Header]\n");
    printf("  Src Port : %d\n", ntohs(tcp->tcp_sport));
    printf("  Dst Port : %d\n", ntohs(tcp->tcp_dport));
    printf("  TCP Header Len : %d bytes\n", tcp_header_len);

    /* Application 계층 데이터(HTTP Message) 출력 */
    int total_headers_len = sizeof(struct ethheader) + ip_header_len + tcp_header_len;
    int payload_len = header->caplen - total_headers_len;

    printf("[HTTP Message]\n");
    if (payload_len > 0) {
        const u_char *payload = packet + total_headers_len;
        printf("  Payload Length : %d bytes\n", payload_len);
        printf("  ---------------------------------------------\n  ");
        for (int i = 0; i < payload_len; i++) {
            unsigned char c = payload[i];
            if (isprint(c) || c == '\n' || c == '\r') {
                putchar(c);
            } else {
                putchar('.');
            }
        }
        printf("\n  ---------------------------------------------\n");
    } else {
        printf("  (no payload / payload length 0)\n");
    }
    printf("=========================================================\n\n");
}

int main(int argc, char *argv[]) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";        /* TCP protocol만을 대상으로 진행 (UDP는 무시) */
    bpf_u_int32 net = 0, mask = 0;
    const char *iface = (argc > 1) ? argv[1] : DEFAULT_IFACE;

    /* 캡처할 네트워크 정보 획득 (필터 컴파일용) */
    if (pcap_lookupnet(iface, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Warning: could not get netmask for device %s: %s\n", iface, errbuf);
        net = 0;
    }

    /* Step 1: Open live pcap session on NIC, promiscuous mode 활성화 */
    handle = pcap_open_live(iface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", iface, errbuf);
        return 2;
    }

    /* Step 2: Compile filter_exp into BPF pseudo-code, apply filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    printf("[*] Sniffing TCP packets on interface: %s\n", iface);
    printf("[*] Press Ctrl+C to stop.\n\n");

    /* Step 3: Capture packets, 캡처될 때마다 got_packet 호출 */
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}
