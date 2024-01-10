#include <pcap.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "hacking.h"
#include "network.h"
#include "packet_display.h"
#include "ethertypes.h"

void pcap_fatal(const char *, const char *);
void decodeEthernet(FILE * fp, const unsigned char *);
void decodeIP(FILE * fp, const unsigned char *);
unsigned int decodeTCP(FILE * fp, const unsigned char *);

void caught_packet(unsigned char *,
        const struct pcap_pkthdr *, 
             const unsigned char *
                );

int main(int argc, char ** argv) {
    struct pcap_pkthdr cap_header;
    const unsigned char *packet, *pkt_data;
    char errbuf[PCAP_ERRBUF_SIZE];
    char * device;

    pcap_t *pcap_handle;

    device = pcap_lookupdev(errbuf);
    if (device == NULL)
        pcap_fatal("pcap_lookupdev", errbuf);

    //printf("Sniffing on device %s\n", device);
    
    pcap_handle = pcap_open_live(device, 4096, 1, 0, errbuf);
    if (pcap_handle == NULL)
        pcap_fatal("pcap_open_live", errbuf);

    pcap_loop(pcap_handle, 1, caught_packet, NULL);
    pcap_close(pcap_handle);
    
}

void caught_packet(unsigned char *user_args,
                   const struct pcap_pkthdr *cap_header,
                   const unsigned char *packet) 
{
    int tcp_header_length;
    int total_header_size;
    int pkt_data_len;
    int data_len;
    unsigned char *pkt_data;
    
    FILE * fp;
    fp = stdout;

    HTML_Start(fp);
    
    // Always ethernet
    // Feed a blank header in so we can do further analysis after print
    const struct ether_hdr *ethernet_header; 
    data_len = decodeEthernet(fp, packet, ethernet_header);
 
    
    // Decide how we want to decode the packet contents

    int ret = -1;
    switch (ether_type) {
        case IPV4 : ret = decodeIPV4() break;
        case IPV6 : ret = decodeIPV6() break; 
        case ARP : ret = decodeARP() break;
        default ret = -1; break;
    }
    // What does eth packet contain?
    
    decodeIP(fp, packet+ETHER_HDR_LEN);
    tcp_header_length = decodeTCP(fp, packet+ETHER_HDR_LEN+sizeof(struct ip_hdr));




    total_header_size = ETHER_HDR_LEN + sizeof(struct ip_hdr) + tcp_header_length;
    pkt_data = (unsigned char *) packet + total_header_size;
    pkt_data_len = cap_header->len - total_header_size;

    if (pkt_data_len > 0)  {
        fprintf(fp, "\t\t\t%u bytes of packet data\n", pkt_data_len);
        HTMLdump(fp, pkt_data, pkt_data_len);
    } else {
        fprintf(fp, "\t\t\tNo Packet Data\n");
    }

    fprintf(fp, "\t</div>\n</div>\n</div>\n</body>\n</html>\n");
}


void pcap_fatal(const char *failed_in, const char *errbuf) {
    printf("Fatal Error in %s: %s\n", failed_in, errbuf);
    exit(1);
}



void decodeEthernet(FILE * fp, 
        const unsigned char * header_start, 
        const struct ether_hdr *ethernet_header)
{
    ethernet_header = (const struct ether_hdr *) header_start;
    //printf("[[  Layer 2 :: Ethernet Header  ]]\n");

    //printf("[ Source: %02x", ethernet_header->ether_src_addr[0]);
    //for (int i = 1; i < ETHER_ADDR_LEN; i++)
    //    printf(":%02x", ethernet_header->ether_src_addr[i]);


    //printf("[ Dest: %02x", ethernet_header->ether_dest_addr[0]);
    //for (int i = 1; i < ETHER_ADDR_LEN; i++)
    //    printf(":%02x", ethernet_header->ether_dest_addr[i]);
    //printf("\tType: %hu ]\n", ntohs(ethernet_header->ether_type));


    fprintf(fp, "%s", ETH_to_HTML(ethernet_header, "red"));
}


void decodeIP(FILE * fp, const unsigned char *header_start)
{
    const struct ip_hdr *ip_header;

    ip_header = (const struct ip_hdr *) header_start;
    //printf("\t((  Layer 3 ::: IP Header   ))\n");
    
    struct in_addr addr; 
    addr.s_addr = ip_header->ip_src_addr;

    //printf("\t( Source : %s\t", inet_ntoa(addr));

    addr.s_addr = ip_header->ip_dest_addr;
    //printf("Dest: %s )\n", inet_ntoa(addr));

    //printf("\t( Type: %u\t", (unsigned int) ip_header->ip_type);
    //printf("ID: %hu\tLength: %hu )\n", ntohs(ip_header->ip_id), ntohs(ip_header->ip_len));

    fprintf(fp, "%s", IP_to_HTML(ip_header, "blue"));
}



unsigned int decodeTCP(FILE * fp, const unsigned char * header_start)
{
    unsigned int header_size;
    const struct tcp_hdr *tcp_header;

    tcp_header = (const struct tcp_hdr *) header_start;
    header_size = 4 * tcp_header->tcp_offset;

    //printf("\t\t{{  Layer 4 :::: TCP Header   }}\n");
    //printf("\t\t{ Src Port: %hu\t", ntohs(tcp_header->tcp_src_port));
    //printf("Dest Port: %hu }\n", ntohs(tcp_header->tcp_dest_port));
    //printf("\t\t{ Seq #:%u\t", ntohl(tcp_header->tcp_seq));
    //printf("Ack #: %u }\n", ntohl(tcp_header->tcp_ack));
    //printf("\t\t{ Header Size: %u\tFlags: ", header_size);

    /*
    if (tcp_header->tcp_flags & TCP_FIN)
        printf("FIN ");
    if (tcp_header->tcp_flags & TCP_SYN)
        printf("SYN ");
    if (tcp_header->tcp_flags & TCP_RST)
        printf("RST ");
    if (tcp_header->tcp_flags & TCP_PUSH)
        printf("PUSH ");
    if (tcp_header->tcp_flags & TCP_ACK)
        printf("ACK ");
    if (tcp_header->tcp_flags & TCP_URG)
        printf("URG ");
    printf(" }\n");
    */
    fprintf(fp, "%s", TCP_to_HTML(tcp_header, "green"));

    return header_size;
}
