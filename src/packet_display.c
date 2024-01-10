#include <pcap.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "network.h"
#include "packet_display.h"


#define STYLESHEET "styles.css"


/*
 * HTML_Start
 * Print the boilerplate stuff at the beginning of the HTML file
 */
void HTML_Start(FILE * fp) {
    fprintf(fp, 
    "<html> \n\
        <head> \n\
            <title>Packet Slicer</title> \n\
            <meta name='description' content='Our first page'> \n\
            <link rel='stylesheet' href='%s'> \n\
        </head> \n\
        <body>\n", STYLESHEET);
}


/*
 * ETH_to_HTML()
 * return String containing a Ethernet header and its contents
 */
char * ETH_to_HTML(const struct ether_hdr * hdr, char * border_color) {
    char * buffer = malloc(512);
    memset(buffer, '\0', 512);

    sprintf(buffer,
"\t<div class='packet_layer eth_packet_layer'>\n\
\t\t<div class='packet_header eth_packet_header'> \n\
\t\t<h2>Ethernet Header</h2> \n\
\t\t<ul> \n\
\t\t\t<li>Source: %hhX:%hhX:%hhX:%hhX:%hhX:%hhX</li> \n\
\t\t\t<li>Destination: %hhX:%hhX:%hhX:%hhX:%hhX:%hhX</li> \n\
\t\t\t<li>Type: %hu </li> \n\
\t\t</ul>\n\
\t\t</div>",
    hdr->ether_src_addr[0], hdr->ether_src_addr[1],
    hdr->ether_src_addr[2], hdr->ether_src_addr[3],
    hdr->ether_src_addr[4], hdr->ether_src_addr[5],
    hdr->ether_dest_addr[0], hdr->ether_dest_addr[1],
    hdr->ether_dest_addr[2], hdr->ether_dest_addr[3],
    hdr->ether_dest_addr[4], hdr->ether_dest_addr[5],
    ntohs(hdr->ether_type));

    return buffer;
}


/*
 *  
 */
char * IP_to_HTML(const struct ip_hdr * hdr, char * border_color) {
    char * buffer = malloc(512);
    memset(buffer, '\0', 512);


    struct in_addr src_addr, dest_addr;
    src_addr.s_addr = hdr->ip_src_addr;
    dest_addr.s_addr = hdr->ip_dest_addr;

    sprintf(buffer,
    "<div class='packet_layer ip_packet_layer'>\n\
    \t<div class='packet_header ip_packet_header'>\n\
    \t<h2>IP Header</h2>\n\
    \t<ul> \n\
    \t\t<li>Source: %s</li> \n\
    \t\t<li>Destination: %s</li> \n\
    \t</ul> \n\
    \t<ul> \n\
    \t\t<li>Type: %u </li> \n\
    \t\t<li>ID: %hu </li> \n\
    \t\t<li>Length: %hu </li> \n\
    \t</ul>\n\
    \t</div>\n",
       inet_ntoa(src_addr),
       inet_ntoa(dest_addr),
       (unsigned int) hdr->ip_type,
       ntohs(hdr->ip_id),
       ntohs(hdr->ip_len));

    return buffer;
}



char * TCP_to_HTML(const struct tcp_hdr * hdr, char * border_color) {
    char * buffer = malloc(512);
    memset(buffer, '\0', 512);

    unsigned int header_size;

    header_size = 4 * hdr->tcp_offset;



    //printf("\t\t{{  Layer 4 :::: TCP Header   }}\n");
    //printf("\t\t{ Src Port: %hu\t", ntohs(tcp_header->tcp_src_port));
    //printf("Dest Port: %hu }\n", ntohs(tcp_header->tcp_dest_port));
    //printf("\t\t{ Seq #:%u\t", ntohl(tcp_header->tcp_seq));
    //printf("Ack #: %u }\n", ntohl(tcp_header->tcp_ack));
    //printf("\t\t{ Header Size: %u\tFlags: ", header_size);


    sprintf(buffer,
    "<div class='packet_layer tcp_packet_layer'>\n\
    \t<div class='packet_header tcp_packet_header'> \n\
    \t<h2>TCP Header</h2>\n\
    \t<ul> \n\
    \t\t<li>Source port: %hu</li> \n\
    \t\t<li>Destination port: %hu</li> \n\
    \t</ul> \n\
    \t<ul> \n\
    \t\t<li>Seq #: %u</li> \n\
    \t\t<li>Ack #: %u</li> \n\
    \t\t<li>Header Size: %u \n\
    \t</ul>\n\
    \t</div>",
    ntohs(hdr->tcp_src_port),
    ntohs(hdr->tcp_dest_port),
    ntohl(hdr->tcp_seq),
    ntohl(hdr->tcp_ack),
    header_size
    );

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

    return buffer;
}


// dumps raw memory in hex byte and printable split format
void HTMLdump(FILE * fp, const unsigned char *data_buffer, const unsigned int length) {
	unsigned char byte;
	unsigned int i, j;
    fprintf(fp, "<div class='packet_body'><div class='hex_bytes'><ul><li>");
	for(i=0; i < length; i++)
    {
		byte = data_buffer[i];
		fprintf(fp, "%02x ", data_buffer[i]);  // display byte in hex
		if(((i%16)==15))
        {
			fprintf(fp, "</li>\n<li>"); // end of the dump line (each line 16 bytes)
		} else if (i == length-1) {
            fprintf(fp, "</li>\n");
        }
	}
    fprintf(fp, "</ul></div><div class='ascii_bytes'><li>");
    for (i=0; i < length; i++)
    {
		byte = data_buffer[i];

        if((byte > 31) && (byte < 127)) // outside printable char range
            printf("%c", byte);
        else
            printf(".");

		if(((i%16)==15))
        {
			fprintf(fp, "</li>\n<li>"); // end of the dump line (each line 16 bytes)
		} else if (i == length-1) {
            fprintf(fp, "</li>\n");
        }
    }
    fprintf(fp, "</div></div>");
}



char * toHTML() {
    return NULL;
}
