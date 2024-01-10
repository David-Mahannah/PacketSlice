#ifndef ETHERTYPES_H
#define ETHERTYPES_H

#define IPV4 0x0800 	                    // Internet Protocol version 4 (IPv4)
#define ARP  0x0806 	                    // Address Resolution Protocol (ARP)
#define WAKE_ON_LAN 0x0842 	                // Wake-on-LAN[8]
#define STREAM_RESERVATION_PROTOCOL 0x22EA 	// Stream Reservation Protocol
#define AVTP 0x22F0 	                    // Audio Video Transport Protocol (AVTP)
#define IETF_TRILL 0x22F3 	                // IETF TRILL Protocol
#define DEC_MOP_RC 0x6002 	                // DEC MOP RC
#define DEC_NET 0x6003 	                    // DECnet Phase IV, DNA Routing
#define DEC_LAT 0x6004                      // DEC LAT
#define RARP 0x8035 	                    // Reverse Address Resolution Protocol (RARP)
#define APPLE_TALK 0x809B 	                // AppleTalk (EtherTalk)
#define AARP 0x80F3 	                    // AppleTalk Address Resolution Protocol (AARP)
#define VLAN_TAGGED_FRAME 0x8100            // VLAN-tagged frame (IEEE 802.1Q) and Shortest Path Bridging IEEE 802.1aq with NNI compatibility[9]
#define SLPP 0x8102                         // Simple Loop Prevention Protocol (SLPP)
#define VLACP 0x8103 	                    // Virtual Link Aggregation Control Protocol (VLACP)
#define IPX 0x8137 	                        // IPX
#define QNX_QNET 0x8204                     // QNX Qnet
#define IPV6 0x86DD 	                    // Internet Protocol Version 6 (IPv6)
#define ETH_FLOW_CONTROL 0x8808 	        // Ethernet flow control
#define ETH_SLOW 0x8809 	                // Ethernet Slow Protocols[10] such as the Link Aggregation Control Protocol (LACP)
#define COBRA_NET 0x8819 	                // CobraNet
#define MPLS_UNICAST 0x8847 	            // MPLS unicast
#define MPLS_MULTICAST 0x8848 	            // MPLS multicast
#define PPPOE_DISCOVERY 0x8863 	            // PPPoE Discovery Stage
#define PPPOE_SESSION 0x8864 	            // PPPoE Session Stage
#define HOMEPLUG 0x887B                     // HomePlug 1.0 MME
#define EAP_OVERR_LAN 0x888E 	            // EAP over LAN (IEEE 802.1X)
#define PROFINET 0x8892 	                // PROFINET Protocol
#define HYPERSCSI 0x889A 	                // HyperSCSI (SCSI over Ethernet)
#define ATA_OVER_ETHERNET 0x88A2            // ATA over Ethernet
#define ETHERCAT 0x88A4 	                // EtherCAT Protocol
#define SERVICE_VLAN 0x88A8 	            // Service VLAN tag identifier (S-Tag) on Q-in-Q tunnel
#define ETHERNET_POWERLINK 0x88AB 	        // Ethernet Powerlink[citation needed]
#define GOOSE 0x88B8 	                    // GOOSE (Generic Object Oriented Substation event)
#define GSE 0x88B9 	                        // GSE (Generic Substation Events) Management Services
#define SV 0x88BA 	                        // SV (Sampled Value Transmission)
#define MIKROTIK 0x88BF                 	// MikroTik RoMON (unofficial)
#define LLDP 0x88CC 	                    // Link Layer Discovery Protocol (LLDP)
#define SECROS_III 0x88CD 	                // SERCOS III
#define HOMEPLUG_GREEN_PHY 0x88E1 	        // HomePlug Green PHY
#define MEDIA_REDUNDANCY 0x88E3 	        // Media Redundancy Protocol (IEC62439-2)
#define MAC_SEC 0x88E5 	                    // IEEE 802.1AE MAC security (MACsec)
#define PPB 0x88E7 	                        // Provider Backbone Bridges (PBB) (IEEE 802.1ah)
#define PTP 0x88F7 	                        // Precision Time Protocol (PTP) over IEEE 802.3 Ethernet
#define NC_SI 0x88F8 	                    // NC-SI
#define PRP 0x88FB 	                        // Parallel Redundancy Protocol (PRP)
#define CFM 0x8902                          // IEEE 802.1ag Connectivity Fault Management (CFM) Protocol / ITU-T Recommendation Y.1731 (OAM)
#define FCoE 0x8906 	                    // Fibre Channel over Ethernet (FCoE)
#define FCoe_INIT 0x8914 	                // FCoE Initialization Protocol
#define ROCE 0x8915 	                    // RDMA over Converged Ethernet (RoCE)
#define TTE 0x891D 	                        // TTEthernet Protocol Control Frame (TTE)
#define IEEE_NET_ENABLE 0x893a              // 1905.1 IEEE Protocol
#define HSR 0x892F 	                        // High-availability Seamless Redundancy (HSR)
#define ETH_CONFIG_TESTING 0x9000 	        // Ethernet Configuration Testing Protocol[11]
#define REDUNDANCY_TAG 0xF1C1 	            // Redundancy Tag (IEEE 802.1CB Frame Replication and Elimination for Reliability) 

#endif 
