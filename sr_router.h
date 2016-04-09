/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_nat.h"

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

#define ICMP_ECHO_REQUEST_CODE 0
#define ICMP_ECHO_REQUEST_TYPE 8
#define ICMP_ECHO_REPLY_TYPE 0
#define ICMP_UNREACHABLE_TYPE 3
#define ICMP_TIME_EXCEEDED_TYPE 11
#define ICMP_TIME_EXCEEDED_CODE 0
#define ICMP_DESTINATION_NET_CODE 0
#define ICMP_DESTINATION_HOST_CODE 1
#define ICMP_PORT_CODE 3

/* NAT internal and external interfaces */
#define INTERNAL_INTERFACE "eth1"
#define EXTERNAL_INTERFACE "eth2"

/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   /* socket to server */
    char user[32]; /* user name */
    char host[32]; /* host name */ 
    char template[30]; /* template name if any */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    struct sr_arpcache cache;   /* ARP cache */
    pthread_attr_t attr;
    FILE* logfile;
    int enable_nat;
    struct sr_nat nat;
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );
void sr_handle_arp_packet(struct sr_instance*, uint8_t *, unsigned int, char *);
void sr_handle_ip_packet(struct sr_instance*, uint8_t *, unsigned int, char *);
void sr_handle_icmp_packet(struct sr_instance*, uint8_t *, unsigned int, char *);
void sr_nat_handle_ip_packet(struct sr_instance*, uint8_t *, unsigned int, char *);
void sr_nat_handle_icmp_packet(struct sr_instance*, uint8_t *, unsigned int, char *);
void sr_nat_handle_icmp_internal(struct sr_instance*, uint8_t *, unsigned int, char *);
void sr_nat_handle_icmp_external(struct sr_instance*, uint8_t *, unsigned int, char *);
void sr_nat_handle_tcp_packet(struct sr_instance*, uint8_t *, unsigned int, char *);
void sr_nat_handle_tcp_internal(struct sr_instance*, uint8_t *, unsigned int, char *);
void sr_nat_handle_tcp_external(struct sr_instance*, uint8_t *, unsigned int, char *);
void sr_forward_ip_packet(struct sr_instance*, uint8_t *, unsigned int, char *);
struct sr_if* sr_ip_destined_for_router_interfaces(struct sr_instance*, uint32_t);
int sr_ip_sanity_check(uint8_t *, unsigned int, sr_ip_hdr_t *, sr_icmp_hdr_t *);
void sr_ip_recompute_checksum(sr_ip_hdr_t *);
struct sr_rt* sr_longest_prefix_match(struct sr_instance*, uint32_t);
void sr_add_ethernet_header_and_send_packet(struct sr_instance*, uint32_t, uint8_t*, uint8_t*, unsigned int, uint16_t);
void sr_send_arp_reply(struct sr_instance*, uint8_t*, char *);
void sr_send_arp_request(struct sr_instance*, uint8_t*);
void sr_process_arp_reply(struct sr_instance*, uint8_t*);
void sr_send_icmp(struct sr_instance*, uint8_t*, uint8_t, uint8_t);

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );

#endif /* SR_ROUTER_H */
