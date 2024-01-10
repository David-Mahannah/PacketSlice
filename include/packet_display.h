#ifndef PACKET_DISPLAY_H
#define PACKET_DISPLAY_H

#include "network.h"

/*
 * ETH_to_HTML()
 * return String containing a Ethernet header and its contents
 */
char * ETH_to_HTML();


/*
 * IP_to_HTML()
 *
 */
char * IP_to_HTML();


/*
 * TCP_to_HTML()
 *
 */
char * TCP_to_HTML();


void HTMLdump();

#endif
